BEGIN;
SET LOCAL ROLE :"owner_role";
SET LOCAL search_path = pg_catalog, pg_temp;

CREATE FUNCTION softteros_enquiries.guard_enquiry() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'New' OR NEW.version <> 1 THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid enquiry transition';
        END IF;
    ELSE
        IF (NEW.organization_id, NEW.enquiry_id, NEW.contact_name, NEW.contact_email,
            NEW.destination, NEW.traveller_count, NEW.travel_start, NEW.travel_end,
            NEW.created_by, NEW.creator_membership_id, NEW.created_at)
           IS DISTINCT FROM
           (OLD.organization_id, OLD.enquiry_id, OLD.contact_name, OLD.contact_email,
            OLD.destination, OLD.traveller_count, OLD.travel_start, OLD.travel_end,
            OLD.created_by, OLD.creator_membership_id, OLD.created_at)
           OR NEW.version <> OLD.version + 1 OR NEW.last_changed_at < OLD.last_changed_at
           OR NOT ((OLD.state = 'New' AND NEW.state = 'Under review' AND OLD.assignee_membership_id IS NULL)
               OR (OLD.state = 'Under review' AND NEW.state = 'Qualified'
                   AND NEW.assignee_membership_id = OLD.assignee_membership_id)) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid enquiry transition';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER guard_enquiry BEFORE INSERT OR UPDATE ON softteros_enquiries.enquiries
    FOR EACH ROW EXECUTE FUNCTION softteros_enquiries.guard_enquiry();

CREATE FUNCTION softteros_enquiries.immutable_event() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'immutable enquiry event';
END $$;
CREATE TRIGGER immutable_event BEFORE UPDATE OR DELETE ON softteros_enquiries.enquiry_events
    FOR EACH ROW EXECUTE FUNCTION softteros_enquiries.immutable_event();

CREATE FUNCTION softteros_enquiries.guard_receipt() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'immutable command receipt';
    END IF;
    IF OLD.completed OR
       (NEW.organization_id, NEW.membership_id, NEW.request_key, NEW.actor_id,
        NEW.command, NEW.expected_version, NEW.fingerprint_version, NEW.fingerprint)
       IS DISTINCT FROM
       (OLD.organization_id, OLD.membership_id, OLD.request_key, OLD.actor_id,
        OLD.command, OLD.expected_version, OLD.fingerprint_version, OLD.fingerprint)
       OR (OLD.enquiry_id IS NOT NULL AND NEW.enquiry_id IS DISTINCT FROM OLD.enquiry_id) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'immutable command receipt';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER guard_receipt BEFORE UPDATE OR DELETE ON softteros_enquiries.enquiry_command_receipts
    FOR EACH ROW EXECUTE FUNCTION softteros_enquiries.guard_receipt();

-- Structural history check, NOT an authentication or authorization engine.
-- SECURITY DEFINER can see structural rows through the explicit migration policy.
CREATE FUNCTION softteros_enquiries.check_history(org text, id text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    e softteros_enquiries.enquiries%ROWTYPE;
    total bigint;
BEGIN
    SELECT * INTO e FROM softteros_enquiries.enquiries
        WHERE organization_id = org AND enquiry_id = id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid enquiry history';
    END IF;
    SELECT count(*) INTO total FROM softteros_enquiries.enquiry_events
        WHERE organization_id = org AND enquiry_id = id;
    IF total <> e.version OR EXISTS (
        SELECT 1 FROM softteros_enquiries.enquiry_events v
        WHERE v.organization_id = org AND v.enquiry_id = id AND (
            v.resulting_version NOT BETWEEN 1 AND e.version
            OR (v.resulting_version = 1 AND
                (v.actor_id <> e.created_by OR v.membership_id <> e.creator_membership_id OR v.at <> e.created_at))
            OR (v.resulting_version > 1 AND v.assignee_membership_id IS DISTINCT FROM e.assignee_membership_id)
            OR (v.resulting_version = e.version AND (v.new_state <> e.state OR v.at <> e.last_changed_at))
            OR NOT EXISTS (
                SELECT 1 FROM softteros_enquiries.enquiry_command_receipts r
                WHERE r.organization_id = v.organization_id AND r.membership_id = v.membership_id
                  AND r.request_key = v.request_key AND r.event_id = v.event_id
                  AND r.enquiry_id = v.enquiry_id AND r.resulting_version = v.resulting_version
                  AND r.actor_id = v.actor_id AND r.command = v.action AND r.completed
                  AND r.completed_at >= v.at))
    ) OR EXISTS (
        SELECT 1 FROM (
            SELECT at, lag(at) OVER (ORDER BY resulting_version) AS prior
            FROM softteros_enquiries.enquiry_events
            WHERE organization_id = org AND enquiry_id = id
        ) times WHERE at < prior
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid enquiry history';
    END IF;
END $$;

CREATE FUNCTION softteros_enquiries.validate_history() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    r softteros_enquiries.enquiry_command_receipts%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME = 'enquiry_command_receipts' THEN
        -- Read the final row, not an earlier queued pending NEW value.
        SELECT * INTO r FROM softteros_enquiries.enquiry_command_receipts
            WHERE organization_id = NEW.organization_id AND membership_id = NEW.membership_id
              AND request_key = NEW.request_key;
        IF NOT FOUND OR NOT r.completed OR r.enquiry_id IS NULL OR r.event_id IS NULL
            OR r.resulting_version IS NULL OR r.completed_at IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'incomplete command receipt';
        END IF;
        PERFORM softteros_enquiries.check_history(r.organization_id, r.enquiry_id);
    ELSE
        PERFORM softteros_enquiries.check_history(NEW.organization_id, NEW.enquiry_id);
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER enquiry_history AFTER INSERT OR UPDATE ON softteros_enquiries.enquiries
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION softteros_enquiries.validate_history();
CREATE CONSTRAINT TRIGGER event_history AFTER INSERT ON softteros_enquiries.enquiry_events
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION softteros_enquiries.validate_history();
CREATE CONSTRAINT TRIGGER receipt_history AFTER INSERT OR UPDATE ON softteros_enquiries.enquiry_command_receipts
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION softteros_enquiries.validate_history();

CREATE FUNCTION softteros_access.guard_membership_binding() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF (NEW.organization_id, NEW.membership_id, NEW.actor_id)
       IS DISTINCT FROM (OLD.organization_id, OLD.membership_id, OLD.actor_id) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'immutable membership binding';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER membership_binding BEFORE UPDATE ON softteros_access.memberships
    FOR EACH ROW EXECUTE FUNCTION softteros_access.guard_membership_binding();
CREATE FUNCTION softteros_access.guard_grant_binding() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF (NEW.organization_id, NEW.grant_id, NEW.actor_id, NEW.membership_id, NEW.enquiry_id, NEW.capability)
       IS DISTINCT FROM (OLD.organization_id, OLD.grant_id, OLD.actor_id, OLD.membership_id, OLD.enquiry_id, OLD.capability) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'immutable grant binding';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER grant_binding BEFORE UPDATE ON softteros_access.enquiry_transition_grants
    FOR EACH ROW EXECUTE FUNCTION softteros_access.guard_grant_binding();
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA softteros_enquiries FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA softteros_access FROM PUBLIC;
COMMIT;

