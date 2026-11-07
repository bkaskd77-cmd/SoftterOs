package postgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	pg "github.com/bkasdk77-cmd/SoftterOs/internal/platform/postgres"
	"github.com/jackc/pgx/v5/pgproto3"
)

type commitWireMode string

const (
	deliverCommitReply commitWireMode = "deliver"
	dropCommitReply    commitWireMode = "drop-reply"
	dropCommitQuery    commitWireMode = "drop-query"

	commitWireFrameLimit = 64 << 10
	cancelStartupCode    = 80877102
)

type commitWirePoint struct {
	pid            int32
	queryForwarded bool
	replyKinds     string
	ready          byte
}

type commitWireSession struct {
	pid         int32
	ready       byte
	replyFrames int
	err         error
}

// commitWireProxy is limited to the pinned driver's serial, local test traffic.
// It accepts at most four peer sockets, with at most two database sessions.
// Session summaries and errors are read only after done closes.
type commitWireProxy struct {
	ctx      context.Context
	cancel   context.CancelFunc
	dir      string
	mode     commitWireMode
	reached  chan commitWirePoint
	release  chan struct{}
	done     chan struct{}
	sessions []*commitWireSession
	err      error
}

func newCommitWireProxy(t *testing.T, ctx context.Context, target pg.Config, mode commitWireMode) *commitWireProxy {
	t.Helper()
	if !filepath.IsAbs(target.Host) || target.Host != os.Getenv("SOFTTEROS_TEST_SOCKET") ||
		target.Database != os.Getenv("SOFTTEROS_TEST_DATABASE") || target.Database == "" {
		t.Fatal("commit proxy requires the harness's exact Unix-socket database")
	}
	dir, err := os.MkdirTemp("", "softteros-wire-")
	if err != nil {
		t.Fatal("private commit proxy directory", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(dir); err != nil {
			t.Error("remove private commit proxy directory", err)
		}
	})
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: commitWireSocket(dir, target.Port), Net: "unix"})
	if err != nil {
		t.Fatal("private commit proxy listener", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	p := &commitWireProxy{ctx: ctx, cancel: cancel, dir: dir, mode: mode,
		reached: make(chan commitWirePoint, 1), release: make(chan struct{}), done: make(chan struct{})}
	t.Cleanup(func() {
		p.cancel()
		select {
		case <-p.done:
		case <-time.After(3 * time.Second):
			t.Error("commit proxy cleanup exceeded its deadline")
		}
	})
	go p.serve(listener, target)
	return p
}

func commitWireSocket(dir string, port uint16) string {
	return filepath.Join(dir, fmt.Sprintf(".s.PGSQL.%d", port))
}

func (p *commitWireProxy) serve(listener *net.UnixListener, target pg.Config) {
	stopListener := context.AfterFunc(p.ctx, func() { _ = listener.Close() })
	var relays sync.WaitGroup
	defer func() {
		p.cancel()
		_ = listener.Close()
		stopListener()
		relays.Wait()
		close(p.done)
	}()
	for accepted := 0; ; accepted++ {
		client, err := listener.AcceptUnix()
		if err != nil {
			if p.ctx.Err() == nil {
				p.err = err
			}
			return
		}
		if p.ctx.Err() != nil {
			_ = client.Close()
			return
		}
		if accepted == 4 {
			_ = client.Close()
			p.err = errors.New("too many commit proxy sockets")
			p.cancel()
			return
		}
		deadline, _ := p.ctx.Deadline()
		stopClient := context.AfterFunc(p.ctx, func() { _ = client.Close() })
		if err = client.SetDeadline(deadline); err != nil {
			stopClient()
			_ = client.Close()
			if p.ctx.Err() == nil {
				p.err = err
			}
			p.cancel()
			return
		}
		startup, err := readCommitWireStartup(client, target)
		if err != nil || startup == nil || len(p.sessions) == 2 {
			stopClient()
			_ = client.Close()
			if err == nil && startup == nil {
				// pgx can dial a CancelRequest during asynchronous cleanup.
				// Close it locally without opening an upstream connection.
				continue
			}
			if err == nil {
				err = errors.New("unexpected additional commit proxy database session")
			}
			if p.ctx.Err() == nil {
				p.err = err
			}
			p.cancel()
			return
		}
		first := len(p.sessions) == 0
		session := &commitWireSession{}
		p.sessions = append(p.sessions, session)
		relays.Go(func() {
			defer stopClient()
			defer client.Close()
			err := p.relay(client, commitWireSocket(target.Host, target.Port), startup, session, first)
			if err != nil && p.ctx.Err() == nil {
				session.err = err
				p.cancel()
			}
		})
	}
}

// Read after done closes.
func (p *commitWireProxy) relayError() error {
	err := p.err
	for _, session := range p.sessions {
		err = errors.Join(err, session.err)
	}
	return err
}

func readCommitWireStartup(client net.Conn, target pg.Config) ([]byte, error) {
	frame, err := readCommitWireFrame(client, make([]byte, commitWireFrameLimit), false)
	if err != nil {
		return nil, err
	}
	if len(frame) < 8 {
		return nil, errors.New("short commit proxy startup")
	}
	if binary.BigEndian.Uint32(frame[4:8]) == cancelStartupCode {
		return nil, nil
	}
	var startup pgproto3.StartupMessage
	if err := startup.Decode(frame[4:]); err != nil || startup.Parameters["database"] != target.Database ||
		startup.Parameters["user"] != target.User {
		return nil, errors.New("unexpected commit proxy startup target or protocol")
	}
	return frame, nil
}

func (p *commitWireProxy) relay(client net.Conn, upstreamPath string, startup []byte, session *commitWireSession, first bool) error {
	upstream, err := (&net.Dialer{}).DialContext(p.ctx, "unix", upstreamPath)
	if err != nil {
		return err
	}
	defer upstream.Close()
	stopUpstream := context.AfterFunc(p.ctx, func() { _ = upstream.Close() })
	defer stopUpstream()
	deadline, _ := p.ctx.Deadline()
	if err := upstream.SetDeadline(deadline); err != nil {
		return err
	}
	if err := writeCommitWire(upstream, startup); err != nil {
		return err
	}
	buf := make([]byte, commitWireFrameLimit)
	if err := session.relayReady(client, upstream, buf, true); err != nil {
		return err
	}
	for {
		frame, err := readCommitWireFrame(client, buf, true)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		kind := frame[0]
		if first && kind == 'Q' && bytes.Equal(frame[5:], []byte("commit\x00")) {
			err := p.commit(client, upstream, buf, frame, session)
			if err != nil || p.mode != deliverCommitReply {
				return err
			}
			first = false
			continue
		}
		switch kind {
		case 'Q', 'S', 'X', 'P', 'B', 'D', 'E', 'C':
		default:
			return fmt.Errorf("unsupported commit proxy frontend message %q", kind)
		}
		if err := writeCommitWire(upstream, frame); err != nil {
			return err
		}
		switch kind {
		case 'X':
			return nil
		case 'Q', 'S':
			// The fixture uses simple Query and extended groups ending in Sync.
			if err := session.relayReady(client, upstream, buf, false); err != nil {
				return err
			}
		}
	}
}

func (s *commitWireSession) relayReady(client, upstream net.Conn, buf []byte, startup bool) error {
	for {
		frame, err := readCommitWireFrame(upstream, buf, true)
		if err != nil {
			return err
		}
		switch frame[0] {
		case 'R':
			if !startup || !bytes.Equal(frame[5:], []byte{0, 0, 0, 0}) {
				return errors.New("commit proxy expects peer authentication")
			}
		case 'K':
			if !startup || len(frame) < 9 {
				return errors.New("unexpected commit proxy backend identity")
			}
			s.pid = int32(binary.BigEndian.Uint32(frame[5:9]))
		case 'Z':
			if len(frame) != 6 || (startup && (s.pid <= 0 || frame[5] != 'I')) {
				return errors.New("invalid commit proxy ReadyForQuery")
			}
			s.ready = frame[5]
			return writeCommitWire(client, frame)
		}
		if err := writeCommitWire(client, frame); err != nil {
			return err
		}
	}
}

func (p *commitWireProxy) commit(client, upstream net.Conn, buf, query []byte, s *commitWireSession) error {
	if s.ready != 'T' || s.pid <= 0 {
		return errors.New("target COMMIT did not follow an open transaction")
	}
	point := commitWirePoint{pid: s.pid, ready: s.ready}
	var reply []byte
	if p.mode != dropCommitQuery {
		if err := writeCommitWire(upstream, query); err != nil {
			return err
		}
		point.queryForwarded = true
		var err error
		reply, point.replyKinds, err = readCommitWireReply(upstream, buf)
		if err != nil {
			return err
		}
		point.ready = 'I'
		s.ready = 'I'
	}
	p.reached <- point
	select {
	case <-p.release:
	case <-p.ctx.Done():
		return p.ctx.Err()
	}
	if p.mode == deliverCommitReply {
		if err := writeCommitWire(client, reply); err != nil {
			return err
		}
		s.replyFrames = len(point.replyKinds)
	}
	return nil
}

func readCommitWireReply(r io.Reader, buf []byte) ([]byte, string, error) {
	// Keep the entire reply private until its boundary is known. The server
	// can report parameter changes or notices around CommandComplete.
	reply := make([]byte, 0, commitWireFrameLimit)
	var kinds [16]byte
	completed := false
	for i := range kinds {
		frame, err := readCommitWireFrame(r, buf, true)
		if err != nil {
			return nil, "", err
		}
		if len(frame) > cap(reply)-len(reply) {
			return nil, "", errors.New("COMMIT reply exceeded buffer")
		}
		reply = append(reply, frame...)
		kind := frame[0]
		kinds[i] = kind
		switch kind {
		case 'C':
			if completed || !bytes.Equal(frame[5:], []byte("COMMIT\x00")) {
				return nil, "", errors.New("expected one successful PostgreSQL COMMIT completion")
			}
			completed = true
		case 'S', 'N': // ParameterStatus or NoticeResponse
		case 'Z':
			if !completed || !bytes.Equal(frame[5:], []byte{'I'}) {
				return nil, "", errors.New("expected PostgreSQL to be idle after COMMIT")
			}
			return reply, string(kinds[:i+1]), nil
		default:
			return nil, "", fmt.Errorf("unexpected COMMIT reply message %q", kind)
		}
	}
	return nil, "", errors.New("COMMIT reply exceeded frame limit")
}

// Length includes its own four bytes but excludes the type byte. Keep the
// caller's fixed buffer and read exactly one frame even if reads fragment it.
func readCommitWireFrame(r io.Reader, buf []byte, typed bool) ([]byte, error) {
	offset := 0
	if typed {
		offset = 1
	}
	header := offset + 4
	if _, err := io.ReadFull(r, buf[:header]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(buf[offset:header])
	if length < 4 || length > uint32(len(buf)-offset) {
		return nil, errors.New("commit proxy frame length outside buffer")
	}
	end := offset + int(length)
	if _, err := io.ReadFull(r, buf[header:end]); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return buf[:end], nil
}

func writeCommitWire(w io.Writer, frame []byte) error {
	n, err := w.Write(frame)
	if err == nil && n != len(frame) {
		return io.ErrShortWrite
	}
	return err
}

type commitWireByteReader struct{ io.Reader }

func (r commitWireByteReader) Read(b []byte) (int, error) {
	return r.Reader.Read(b[:min(1, len(b))])
}

func TestCommitWireFrameBoundaries(t *testing.T) {
	startup := []byte{0, 0, 0, 9, 0, 3, 0, 0, 0}
	query := []byte("Q\x00\x00\x00\x0bcommit\x00")
	ready := []byte("Z\x00\x00\x00\x05I")
	stream := commitWireByteReader{bytes.NewReader(bytes.Join([][]byte{startup, query, ready}, nil))}
	buf := make([]byte, 32)
	for i, want := range [][]byte{startup, query, ready} {
		got, err := readCommitWireFrame(stream, buf, i != 0)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("fragmented frame %d did not round trip: %v", i, err)
		}
	}
	for _, input := range []string{"Q\xff\xff\xff\xff", "Q\x00\x00\x00\x03", "Q\x00\x00\x00\x05"} {
		if got, err := readCommitWireFrame(bytes.NewBufferString(input), buf, true); err == nil || got != nil {
			t.Fatal("invalid or truncated frame was accepted")
		}
	}
}

func TestCommitWireReplyBoundary(t *testing.T) {
	complete := "C\x00\x00\x00\x0bCOMMIT\x00"
	parameter := "S\x00\x00\x00\x08x\x00y\x00"
	idle := "Z\x00\x00\x00\x05I"
	want := complete + parameter + idle
	buf := make([]byte, commitWireFrameLimit)
	r := commitWireByteReader{bytes.NewBufferString(want)}
	reply, kinds, err := readCommitWireReply(r, buf)
	if err != nil || string(reply) != want || kinds != "CSZ" {
		t.Fatalf("commit cycle with an intervening parameter frame was not preserved: %v", err)
	}
	for _, input := range []string{parameter + idle, complete + "Z\x00\x00\x00\x05T", complete + complete + idle} {
		if reply, kinds, err := readCommitWireReply(bytes.NewBufferString(input), buf); err == nil || reply != nil || kinds != "" {
			t.Fatal("incomplete, non-idle or repeated commit completion was accepted")
		}
	}
}
