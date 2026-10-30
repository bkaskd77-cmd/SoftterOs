\set ON_ERROR_STOP on
-- Test-only pg_temp helpers execute with the CURRENT restricted role.
CREATE FUNCTION pg_temp.assert_true(ok boolean, label text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    IF ok IS DISTINCT FROM true THEN RAISE EXCEPTION 'assertion failed: %', label; END IF;
END $$;
CREATE FUNCTION pg_temp.expect_error(command text, expected text, label text, fragment text DEFAULT '')
RETURNS void LANGUAGE plpgsql AS $$
DECLARE actual text; detail text;
BEGIN
    BEGIN
        EXECUTE command;
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS actual = RETURNED_SQLSTATE, detail = MESSAGE_TEXT;
        IF actual = expected AND position(fragment IN detail) > 0 THEN RETURN; END IF;
        RAISE EXCEPTION 'wrong failure for %: expected %, received % (%)', label, expected, actual, detail;
    END;
    RAISE EXCEPTION 'missing failure for %', label;
END $$;

-- Synthetic fixture builders, not a callable application API or authorization engine.
CREATE FUNCTION pg_temp.capture(id text, member text, receipt_member text DEFAULT NULL,
    event_actor text DEFAULT NULL, event_member text DEFAULT NULL) RETURNS void LANGUAGE plpgsql AS $$
DECLARE org text := softteros_access.context_organization();
        actor text := softteros_access.context_actor();
        audit_actor text := coalesce(event_actor, actor);
        audit_member text := coalesce(event_member, member);
        rmember text := coalesce(receipt_member, audit_member);
BEGIN
    INSERT INTO softteros_enquiries.enquiries VALUES
        (org,id,'Synthetic Contact','contact@example.com','Norway',2,
         '2020-02-29','2020-03-02','New',actor,member,
         '2026-10-29 12:00:00.123456+00',NULL,1,'2026-10-29 12:00:00.123456+00');
    INSERT INTO softteros_enquiries.enquiry_command_receipts
        (organization_id,membership_id,request_key,actor_id,command,expected_version,fingerprint_version,fingerprint)
        VALUES (org,rmember,id||'-1',audit_actor,'enquiry.created',0,1,decode(repeat('ab',32),'hex'));
    INSERT INTO softteros_enquiries.enquiry_events
        (organization_id,event_id,enquiry_id,request_key,active_organization_id,actor_id,membership_id,
         action,capability,outcome,actor_authority_revision,organization_authority_revision,
         new_state,resulting_version,at)
        VALUES (org,id||'-event-1',id,id||'-1',org,audit_actor,audit_member,'enquiry.created','enquiries.create',
                'success',1,1,'New',1,'2026-10-29 12:00:00.123456+00');
    UPDATE softteros_enquiries.enquiry_command_receipts SET enquiry_id=id,event_id=id||'-event-1',
        resulting_version=1,completed=true,completed_at='2026-10-29 12:00:00.123456+00'
        WHERE organization_id=org AND membership_id=rmember AND request_key=id||'-1';
END $$;
CREATE FUNCTION pg_temp.progress(id text, member text, qualifying boolean, grant_name text DEFAULT NULL) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    org text := softteros_access.context_organization();
    actor text := softteros_access.context_actor();
    v bigint := CASE WHEN qualifying THEN 3 ELSE 2 END;
    changed integer;
    instant timestamptz := CASE WHEN qualifying THEN '2026-10-29 12:02:00.123456+00'::timestamptz
                               ELSE '2026-10-29 12:01:00.123456+00'::timestamptz END;
    action text := CASE WHEN qualifying THEN 'enquiry.qualified' ELSE 'enquiry.review_started' END;
BEGIN
    UPDATE softteros_enquiries.enquiries SET state=CASE WHEN qualifying THEN 'Qualified' ELSE 'Under review' END,
        version=v,assignee_membership_id=member,last_changed_at=instant
        WHERE organization_id=org AND enquiry_id=id AND version=v-1;
    GET DIAGNOSTICS changed = ROW_COUNT;
    PERFORM pg_temp.assert_true(changed=1,'fixture conditional update');
    INSERT INTO softteros_enquiries.enquiry_command_receipts
        (organization_id,membership_id,request_key,actor_id,command,expected_version,fingerprint_version,fingerprint)
        VALUES (org,member,id||'-'||v,actor,action,v-1,1,decode(repeat('cd',32),'hex'));
    INSERT INTO softteros_enquiries.enquiry_events VALUES
        (org,id||'-event-'||v,id,id||'-'||v,org,actor,member,coalesce(grant_name,CASE WHEN qualifying THEN 'g-qualify' ELSE 'g-review' END),
         action,CASE WHEN qualifying THEN 'enquiries.qualify' ELSE 'enquiries.review' END,'success',1,1,
         CASE WHEN qualifying THEN 'Under review' ELSE 'New' END,
         CASE WHEN qualifying THEN 'Qualified' ELSE 'Under review' END,
         CASE WHEN qualifying THEN member END,member,v-1,v,instant);
    UPDATE softteros_enquiries.enquiry_command_receipts SET enquiry_id=id,event_id=id||'-event-'||v,
        resulting_version=v,completed=true,completed_at=instant
        WHERE organization_id=org AND membership_id=member AND request_key=id||'-'||v;
END $$;

-- Fixture authority is explicitly pre-resolved synthetic data.
BEGIN;
SET LOCAL ROLE :"writer_role";
SELECT set_config('softteros.actor_id','actor-1',true),set_config('softteros.organization_id','org-1',true);
INSERT INTO softteros_access.actors VALUES ('actor-1');
INSERT INTO softteros_access.organizations VALUES ('org-1');
INSERT INTO softteros_access.actor_authority_fences VALUES ('actor-1',1);
INSERT INTO softteros_access.organization_authority_fences VALUES ('org-1',1);
INSERT INTO softteros_access.memberships VALUES
 ('org-1','member-1','actor-1',true,false,'2000-01-01+00','9999-01-01+00'),
 ('org-1','member-1b','actor-1',true,false,'2000-01-01+00','9999-01-01+00');
SELECT set_config('softteros.organization_id','org-2',true);
INSERT INTO softteros_access.organizations VALUES ('org-2');
INSERT INTO softteros_access.organization_authority_fences VALUES ('org-2',1);
INSERT INTO softteros_access.memberships VALUES ('org-2','member-2','actor-1',true,false,'2000-01-01+00','9999-01-01+00');
SELECT set_config('softteros.organization_id','org-1',true),set_config('softteros.actor_id','actor-2',true);
INSERT INTO softteros_access.actors VALUES ('actor-2');
INSERT INTO softteros_access.actor_authority_fences VALUES ('actor-2',1);
INSERT INTO softteros_access.memberships VALUES ('org-1','member-3','actor-2',true,false,'2000-01-01+00','9999-01-01+00');
INSERT INTO softteros_access.membership_enquiry_capabilities
 SELECT 'org-1','member-3',cap FROM unnest(ARRAY['enquiries.create','enquiries.review','enquiries.qualify']) cap;
-- Missing-fence positive identity anchors for a focused helper denial.
SELECT set_config('softteros.actor_id','actor-3',true);
INSERT INTO softteros_access.actors VALUES ('actor-3');
INSERT INTO softteros_access.memberships VALUES ('org-1','member-4','actor-3',true,false,'2000-01-01+00','9999-01-01+00');
SELECT set_config('softteros.actor_id','actor-1',true),set_config('softteros.organization_id','org-3',true);
INSERT INTO softteros_access.organizations VALUES ('org-3');
INSERT INTO softteros_access.memberships VALUES ('org-3','member-5','actor-1',true,false,'2000-01-01+00','9999-01-01+00');
COMMIT;

-- Successful complete commands and tenant-local identifier collision.
BEGIN;
SET LOCAL ROLE :"runtime_role";
SELECT set_config('softteros.actor_id','actor-1',true),set_config('softteros.organization_id','org-1',true);
SELECT pg_temp.capture('enquiry-1','member-1');
COMMIT;
BEGIN;
SET LOCAL ROLE :"runtime_role";
SELECT set_config('softteros.actor_id','actor-1',true),set_config('softteros.organization_id','org-2',true);
SELECT pg_temp.capture('enquiry-1','member-2');
COMMIT;

BEGIN;
SET LOCAL ROLE :"writer_role";
SELECT set_config('softteros.actor_id','actor-2',true),set_config('softteros.organization_id','org-1',true);
INSERT INTO softteros_access.enquiry_transition_grants VALUES
 ('org-1','g-review','actor-2','member-3','enquiry-1','enquiries.review',true,false,'2000-01-01+00','9999-01-01+00'),
 ('org-1','g-qualify','actor-2','member-3','enquiry-1','enquiries.qualify',true,false,'2000-01-01+00','9999-01-01+00');
COMMIT;
BEGIN;
SET LOCAL ROLE :"runtime_role";
SELECT set_config('softteros.actor_id','actor-2',true),set_config('softteros.organization_id','org-1',true);
SELECT pg_temp.progress('enquiry-1','member-3',false);
COMMIT;
BEGIN;
SET LOCAL ROLE :"runtime_role";
SELECT set_config('softteros.actor_id','actor-2',true),set_config('softteros.organization_id','org-1',true);
SELECT pg_temp.progress('enquiry-1','member-3',true);
COMMIT;

BEGIN;
SET LOCAL ROLE :"runtime_role";
SELECT pg_temp.assert_true(NOT (SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolbypassrls OR rolcanlogin OR rolreplication
    FROM pg_roles WHERE rolname=current_user),'restricted effective role attributes');
SELECT pg_temp.assert_true((SELECT bool_and(relrowsecurity AND relforcerowsecurity)
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname IN ('softteros_access','softteros_enquiries') AND relkind='r'),'forced RLS');
SELECT pg_temp.assert_true((SELECT count(*)=0 FROM softteros_enquiries.enquiries),'missing context read denial');
SELECT pg_temp.expect_error($q$SELECT pg_temp.capture('missing-context','member-1')$q$,'42501','missing context write');
SELECT set_config('softteros.organization_id','org-1',true),set_config('softteros.actor_id','actor-1',true);
SELECT pg_temp.assert_true((SELECT count(*)=1 FROM softteros_enquiries.enquiries),'unfiltered reads tenant scoped');
SELECT pg_temp.assert_true((SELECT count(*)=0 FROM softteros_enquiries.enquiries WHERE organization_id='org-2'),'cross tenant read');
SELECT pg_temp.assert_true((SELECT count(*)=1 FROM softteros_access.actors),'global actors are not directory');
SELECT pg_temp.assert_true((SELECT count(*)=2 FROM softteros_access.memberships WHERE actor_id='actor-1'),'independent same-org memberships');
SELECT pg_temp.assert_true((SELECT state='Qualified' AND version=3 AND assignee_membership_id='member-3'
    AND created_by='actor-1' AND creator_membership_id='member-1'
    AND travel_start=DATE '2020-02-29' AND created_at=TIMESTAMPTZ '2026-10-29 12:00:00.123456+00'
    FROM softteros_enquiries.enquiries),'complete state, creator, historical dates, microseconds');
SELECT pg_temp.assert_true((SELECT count(*)=3 FROM softteros_enquiries.enquiry_events),'three contiguous immutable events');
SELECT pg_temp.assert_true((SELECT count(*)=3 FROM softteros_enquiries.enquiry_command_receipts WHERE completed),'three bound receipts');
SELECT pg_temp.assert_true((SELECT actor_revision=1 AND organization_revision=1
    FROM softteros_access.lock_current_authority('actor-1','org-1')),'lock helper positive control');
SELECT pg_temp.expect_error($q$SELECT * FROM softteros_access.lock_current_authority('actor-2','org-1')$q$,
    '42501','helper actor mismatch','authority context unavailable');
SELECT pg_temp.expect_error($q$SELECT * FROM softteros_access.lock_current_authority('actor-1','org-2')$q$,
    '42501','helper tenant mismatch','authority context unavailable');
SELECT pg_temp.expect_error($q$SELECT softteros_enquiries.check_history('org-1','enquiry-1')$q$,
    '42501','private integrity function inaccessible');
SELECT pg_temp.expect_error($q$UPDATE softteros_access.memberships SET active=false$q$,'42501','runtime authority update');
SELECT pg_temp.expect_error($q$UPDATE softteros_enquiries.enquiries SET created_by='actor-2'$q$,'42501','runtime creator overwrite');
SELECT pg_temp.expect_error($q$INSERT INTO softteros_access.actors VALUES ('invented')$q$,'42501','runtime authority insert');
SELECT pg_temp.expect_error($q$UPDATE softteros_enquiries.enquiry_events SET actor_id='actor-2'$q$,'42501','event tampering');
SELECT pg_temp.expect_error($q$DELETE FROM softteros_enquiries.enquiry_events$q$,'42501','event deletion');
SELECT pg_temp.expect_error($q$UPDATE softteros_enquiries.enquiry_command_receipts SET completed_at=clock_timestamp()
 WHERE membership_id='member-1'$q$,'55000','completed receipt timestamp tampering','immutable command receipt');
SELECT pg_temp.expect_error($q$UPDATE softteros_enquiries.enquiry_command_receipts SET fingerprint=decode(repeat('ef',32),'hex')$q$,
    '42501','receipt fingerprint rebinding denied by column privileges');
SELECT pg_temp.expect_error($q$DELETE FROM softteros_enquiries.enquiry_command_receipts$q$,'42501','receipt deletion');
SELECT pg_temp.expect_error($q$TRUNCATE softteros_enquiries.enquiries$q$,'42501','truncate bypass denied');
SELECT pg_temp.expect_error($q$ALTER TABLE softteros_enquiries.enquiries DISABLE ROW LEVEL SECURITY$q$,'42501','RLS administration denied');
SELECT pg_temp.expect_error($q$CREATE SCHEMA runtime_escape$q$,'42501','schema creation denied');
SELECT pg_temp.expect_error($q$CREATE ROLE runtime_escape$q$,'42501','role administration denied');
SELECT pg_temp.expect_error($q$ALTER TABLE softteros_enquiries.enquiries OWNER TO CURRENT_USER$q$,'42501','ownership denied');

SELECT pg_temp.expect_error($q$INSERT INTO softteros_enquiries.enquiries VALUES
 ('org-2','foreign','Contact','contact@example.com','Norway',1,NULL,NULL,'New','actor-1','member-2',
  '2026-10-29+00',NULL,1,'2026-10-29+00')$q$,'42501','cross tenant write');
SELECT pg_temp.expect_error($q$SELECT pg_temp.capture('foreign-reference','member-2')$q$,
    '23503','same actor foreign membership reference');
SELECT pg_temp.expect_error($q$INSERT INTO softteros_enquiries.enquiries VALUES
 ('org-1','invalid-state','Contact','contact@example.com','Norway',1,NULL,NULL,'Qualified','actor-1','member-1',
  '2026-10-29+00','member-1',3,'2026-10-29+00')$q$,'23514','direct insert qualified','invalid enquiry transition');
SELECT pg_temp.expect_error($q$UPDATE softteros_enquiries.enquiries SET state='Qualified',version=4$q$,
    '23514','repeated qualification','invalid enquiry transition');
SELECT pg_temp.expect_error($q$UPDATE softteros_enquiries.enquiries SET assignee_membership_id='member-1',version=4$q$,
    '23514','reassignment forbidden','invalid enquiry transition');
SELECT pg_temp.expect_error($q$INSERT INTO softteros_enquiries.enquiries VALUES
 ('org-1','missing-event','Contact','contact@example.com','Norway',1,NULL,NULL,'New','actor-1','member-1',
  '2026-10-29+00',NULL,1,'2026-10-29+00'); SET CONSTRAINTS ALL IMMEDIATE$q$,
    '23514','missing event prevents transaction completion','invalid enquiry history');
SELECT pg_temp.assert_true((SELECT count(*)=1 FROM softteros_enquiries.enquiries),'failed transaction has no partial enquiry');
SELECT pg_temp.expect_error($q$INSERT INTO softteros_enquiries.enquiry_command_receipts
 (organization_id,membership_id,request_key,actor_id,command,expected_version,fingerprint_version,fingerprint)
 VALUES ('org-1','member-1','pending','actor-1','enquiry.created',0,1,decode(repeat('ab',32),'hex'));
 SET CONSTRAINTS ALL IMMEDIATE$q$,'23514','pending receipt cannot commit','incomplete command receipt');
SELECT pg_temp.assert_true((SELECT count(*)=3 FROM softteros_enquiries.enquiry_command_receipts),'failed receipt rolled back');
SELECT pg_temp.expect_error($q$SELECT pg_temp.capture('enquiry-1','member-1')$q$,'23505','duplicate enquiry identity');
SELECT pg_temp.expect_error($q$INSERT INTO softteros_enquiries.enquiry_events
 SELECT * FROM softteros_enquiries.enquiry_events WHERE resulting_version=1$q$,'23505','duplicate immutable event');
SELECT pg_temp.expect_error($q$INSERT INTO softteros_enquiries.enquiry_command_receipts
 SELECT * FROM softteros_enquiries.enquiry_command_receipts WHERE resulting_version=1$q$,'23505','duplicate command receipt');
SELECT pg_temp.expect_error($q$SELECT pg_temp.capture('wrong-binding','member-1','member-1b');
 SET CONSTRAINTS softteros_enquiries.receipt_event_binding IMMEDIATE$q$,
 '23503','receipt event action/member/version binding','receipt_event_binding');

SELECT set_config('softteros.actor_id','bad actor',true);
SELECT pg_temp.assert_true((SELECT count(*)=0 FROM softteros_enquiries.enquiries),'malformed actor denies reads');
SELECT pg_temp.expect_error($q$SELECT pg_temp.capture('invalid-context','member-1')$q$,'42501','malformed actor write');
SELECT set_config('softteros.actor_id','unknown-actor',true);
SELECT pg_temp.assert_true((SELECT count(*)=0 FROM softteros_enquiries.enquiries),'unknown actor context denies');
SELECT set_config('softteros.actor_id','actor-2',true),set_config('softteros.organization_id','org-2',true);
SELECT pg_temp.assert_true((SELECT count(*)=0 FROM softteros_enquiries.enquiries),'existing actor without tenant binding denies');
SELECT set_config('softteros.actor_id','actor-1',true),set_config('softteros.organization_id','bad/org',true);
SELECT pg_temp.assert_true((SELECT count(*)=0 FROM softteros_enquiries.enquiries),'malformed organization denies');
SELECT set_config('softteros.actor_id','actor-3',true),set_config('softteros.organization_id','org-1',true);
SELECT pg_temp.expect_error($q$SELECT * FROM softteros_access.lock_current_authority('actor-3','org-1')$q$,
 '42501','missing actor fence','authority context unavailable');
SELECT set_config('softteros.actor_id','actor-1',true),set_config('softteros.organization_id','org-3',true);
SELECT pg_temp.expect_error($q$SELECT * FROM softteros_access.lock_current_authority('actor-1','org-3')$q$,
 '42501','missing organization fence','authority context unavailable');
COMMIT;

-- Same connection: transaction-local context must disappear after commit/rollback.
SET ROLE :"runtime_role";
SELECT pg_temp.assert_true((SELECT count(*)=0 FROM softteros_enquiries.enquiries),'context reset after commit');
BEGIN;
SELECT set_config('softteros.actor_id','actor-1',true),set_config('softteros.organization_id','org-2',true);
SELECT pg_temp.assert_true((SELECT count(*)=1 FROM softteros_enquiries.enquiries),'second organization positive control');
ROLLBACK;
SELECT pg_temp.assert_true((SELECT count(*)=0 FROM softteros_enquiries.enquiries),'context reset after rollback');
RESET ROLE;

-- SET ROLE alone retains the bootstrap superuser as session_user and cannot
-- prove SET ROLE denial. Use a restricted session identity for this test only.
-- This remains a permission test, not a peer-login/authentication test.
SET SESSION AUTHORIZATION :"runtime_role";
SELECT pg_temp.expect_error(format('SET ROLE %I', :'owner_role'),'42501','owner role escalation denied');
SELECT pg_temp.expect_error(format('SET ROLE %I', :'lock_role'),'42501','helper role escalation denied');
RESET SESSION AUTHORIZATION;

-- Ownership/helper metadata and no role escalation; names are supplied by bootstrap.
SELECT pg_temp.assert_true(NOT pg_has_role(:'runtime_role', :'owner_role','MEMBER')
 AND NOT pg_has_role(:'runtime_role', :'writer_role','MEMBER')
 AND NOT pg_has_role(:'runtime_role', :'lock_role','MEMBER'),'no runtime escalation memberships');
SELECT pg_temp.assert_true((SELECT count(*)=0 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname IN ('softteros_access','softteros_enquiries') AND c.relkind='r'
 AND c.relowner IN (to_regrole(:'runtime_role'),to_regrole(:'lock_role'))),'runtime and helper own no tables');
SELECT pg_temp.assert_true((SELECT p.prosecdef AND p.proowner=to_regrole(:'lock_role')
 AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
 FROM pg_proc p WHERE p.oid='softteros_access.lock_current_authority(text,text)'::regprocedure),'restricted helper metadata');
SELECT pg_temp.assert_true(NOT has_schema_privilege(:'runtime_role','softteros_access','CREATE')
 AND NOT has_schema_privilege(:'lock_role','softteros_access','CREATE')
 AND NOT has_table_privilege(:'lock_role','softteros_access.memberships','UPDATE')
 AND NOT EXISTS (SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a
     WHERE p.oid='softteros_access.lock_current_authority(text,text)'::regprocedure
       AND a.grantee=0 AND a.privilege_type='EXECUTE'),'helper least privileges');
BEGIN;
SET LOCAL ROLE :"writer_role";
SELECT set_config('softteros.actor_id','actor-1',true),set_config('softteros.organization_id','org-1',true);
SELECT revision FROM softteros_access.actor_authority_fences WHERE actor_id='actor-1' FOR UPDATE;
SELECT revision FROM softteros_access.organization_authority_fences WHERE organization_id='org-1' FOR UPDATE;
UPDATE softteros_access.memberships SET active=false,revoked=true WHERE membership_id='member-1';
UPDATE softteros_access.organization_authority_fences SET revision=revision+1 WHERE organization_id='org-1';
SELECT pg_temp.expect_error($q$UPDATE softteros_enquiries.enquiries SET state='New'$q$,'42501','writer cannot change business state');
SELECT pg_temp.expect_error($q$UPDATE softteros_access.memberships SET actor_id='actor-2'$q$,'42501','writer cannot rebind membership');
SELECT pg_temp.expect_error($q$UPDATE softteros_access.enquiry_transition_grants SET capability='enquiries.create'$q$,'42501','writer cannot rebind grant');
COMMIT;
BEGIN;
SET LOCAL ROLE :"runtime_role";
SELECT set_config('softteros.actor_id','actor-1',true),set_config('softteros.organization_id','org-1',true);
SET CONSTRAINTS ALL IMMEDIATE;
SELECT pg_temp.assert_true((SELECT count(*)=3 FROM softteros_enquiries.enquiry_events),'historical attribution survives creator revocation');
SELECT pg_temp.assert_true((SELECT organization_revision=2
 FROM softteros_access.lock_current_authority('actor-1','org-1')),'writer revision positive control');
COMMIT;
\echo SQL permission and integrity assertions passed

-- Malformed storage injection under the owner is a structural integrity test,
-- explicitly separate from the restricted-runtime permission tests above.
BEGIN;
SET LOCAL ROLE :"owner_role";
SELECT set_config('softteros.actor_id','actor-1',true),set_config('softteros.organization_id','org-1',true);
SELECT pg_temp.expect_error($q$SELECT pg_temp.capture('mismatched-creator','member-1',NULL,'actor-2','member-3');
 SET CONSTRAINTS ALL IMMEDIATE$q$,'23514','event creator mismatch despite valid foreign keys','invalid enquiry history');
SELECT pg_temp.assert_true((SELECT count(*)=0 FROM softteros_enquiries.enquiries WHERE enquiry_id='mismatched-creator'),
 'bad history rolls back enquiry, event, and receipt');
COMMIT;

BEGIN;
SET LOCAL ROLE :"runtime_role";
SELECT set_config('softteros.actor_id','actor-1',true),set_config('softteros.organization_id','org-2',true);
SELECT pg_temp.expect_error($q$UPDATE softteros_enquiries.enquiries SET state='Under review',version=2,
 assignee_membership_id=NULL$q$,'23514','review requires assignment','enquiry_shape');
SELECT pg_temp.expect_error($q$INSERT INTO softteros_enquiries.enquiries VALUES
 ('org-2','bad-date','Contact','contact@example.com','Norway',1,'2020-03-01',NULL,'New','actor-1','member-2',
  '2026-10-29+00',NULL,1,'2026-10-29+00')$q$,'23514','incomplete travel range','enquiry_dates');
SELECT pg_temp.expect_error($q$INSERT INTO softteros_enquiries.enquiries VALUES
 ('org-2','bad-date','Contact','contact@example.com','Norway',1,'2020-03-02','2020-03-01','New','actor-1','member-2',
  '2026-10-29+00',NULL,1,'2026-10-29+00')$q$,'23514','reversed historical travel range','enquiry_dates');
SELECT pg_temp.expect_error($q$INSERT INTO softteros_enquiries.enquiries VALUES
 ('org-2','bad-time','Contact','contact@example.com','Norway',1,NULL,NULL,'New','actor-1','member-2',
  'infinity',NULL,1,'infinity')$q$,'23514','infinite timestamp','instant_check');
SELECT pg_temp.expect_error($q$INSERT INTO softteros_enquiries.enquiries VALUES
 ('org-2','bad-time','Contact','contact@example.com','Norway',1,NULL,NULL,'New','actor-1','member-2',
  '0001-01-01+00',NULL,1,'0001-01-01+00')$q$,'23514','zero Go timestamp','instant_check');
SELECT pg_temp.expect_error($q$INSERT INTO softteros_enquiries.enquiries VALUES
 ('org-2','bad-count','Contact','contact@example.com','Norway',0,NULL,NULL,'New','actor-1','member-2',
  '2026-10-29+00',NULL,1,'2026-10-29+00')$q$,'23514','invalid traveller count','traveller_count');
SELECT set_config('softteros.organization_id','org-1',true);
SELECT pg_temp.capture('work','member-1');
COMMIT;
BEGIN;
SET LOCAL ROLE :"writer_role";
SELECT set_config('softteros.actor_id','actor-2',true),set_config('softteros.organization_id','org-1',true);
INSERT INTO softteros_access.enquiry_transition_grants VALUES
 ('org-1','work-review','actor-2','member-3','work','enquiries.review',true,false,'2000-01-01+00','9999-01-01+00');
COMMIT;
BEGIN;
SET LOCAL ROLE :"runtime_role";
SELECT set_config('softteros.actor_id','actor-2',true),set_config('softteros.organization_id','org-1',true);
SELECT pg_temp.expect_error($q$SELECT pg_temp.progress('work','member-3',false)$q$,
 '23503','audit grant is scoped to exact enquiry');
SELECT pg_temp.assert_true((SELECT state='New' AND version=1 AND assignee_membership_id IS NULL
 FROM softteros_enquiries.enquiries WHERE enquiry_id='work'),'audit failure rolls back state and assignment');
SELECT pg_temp.assert_true((SELECT count(*)=1 FROM softteros_enquiries.enquiry_events WHERE enquiry_id='work'),
 'audit failure leaves only original event');
SELECT pg_temp.assert_true((SELECT count(*)=1 FROM softteros_enquiries.enquiry_command_receipts WHERE enquiry_id='work'),
 'audit failure rolls back receipt reservation');
SELECT pg_temp.progress('work','member-3',false,'work-review');
COMMIT;
BEGIN;
SET LOCAL ROLE :"writer_role";
SELECT set_config('softteros.actor_id','actor-1',true),set_config('softteros.organization_id','org-1',true);
INSERT INTO softteros_access.enquiry_transition_grants VALUES
 ('org-1','work-other','actor-1','member-1b','work','enquiries.qualify',true,false,'2000-01-01+00','9999-01-01+00');
COMMIT;
BEGIN;
SET LOCAL ROLE :"runtime_role";
SELECT set_config('softteros.actor_id','actor-1',true),set_config('softteros.organization_id','org-1',true);
SELECT pg_temp.expect_error($q$SELECT pg_temp.progress('work','member-1b',true,'work-other')$q$,
 '23514','qualification cannot replace exact assignee','invalid enquiry transition');
SELECT pg_temp.expect_error($q$UPDATE softteros_access.organization_authority_fences SET revision=revision+1$q$,
 '42501','runtime cannot write helper-owned fence privileges');
SELECT pg_temp.assert_true((SELECT state='Under review' AND version=2 AND assignee_membership_id='member-3'
 FROM softteros_enquiries.enquiries WHERE enquiry_id='work'),'non-assignee denial preserves state');
COMMIT;
\echo Extended SQL invariant and rollback assertions passed

