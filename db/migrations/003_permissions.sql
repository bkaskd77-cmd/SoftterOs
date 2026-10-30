BEGIN;
SET LOCAL ROLE :"owner_role";
SET LOCAL search_path = pg_catalog, pg_temp;
GRANT USAGE ON SCHEMA softteros_access TO :"runtime_role", :"writer_role", :"lock_role";
GRANT USAGE ON SCHEMA softteros_enquiries TO :"runtime_role";
GRANT USAGE ON TYPE softteros_access.identifier, softteros_access.instant TO :"runtime_role", :"writer_role";
GRANT EXECUTE ON FUNCTION softteros_access.context_actor(), softteros_access.context_organization()
    TO :"runtime_role", :"writer_role", :"lock_role";

GRANT SELECT ON ALL TABLES IN SCHEMA softteros_access TO :"runtime_role";
GRANT SELECT ON ALL TABLES IN SCHEMA softteros_enquiries TO :"runtime_role";
GRANT INSERT ON softteros_enquiries.enquiries, softteros_enquiries.enquiry_events,
    softteros_enquiries.enquiry_command_receipts TO :"runtime_role";
GRANT UPDATE (state, assignee_membership_id, version, last_changed_at)
    ON softteros_enquiries.enquiries TO :"runtime_role";
GRANT UPDATE (enquiry_id, event_id, resulting_version, completed, completed_at)
    ON softteros_enquiries.enquiry_command_receipts TO :"runtime_role";

GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA softteros_access TO :"writer_role";
GRANT DELETE ON softteros_access.membership_enquiry_capabilities TO :"writer_role";
GRANT UPDATE (active, revoked, valid_from, valid_until) ON softteros_access.memberships,
    softteros_access.enquiry_transition_grants TO :"writer_role";
GRANT UPDATE (revision) ON softteros_access.actor_authority_fences,
    softteros_access.organization_authority_fences TO :"writer_role";
GRANT SELECT ON softteros_access.actor_authority_fences,
    softteros_access.organization_authority_fences TO :"lock_role";
GRANT UPDATE (revision) ON softteros_access.actor_authority_fences,
    softteros_access.organization_authority_fences TO :"lock_role";

ALTER TABLE softteros_access.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE softteros_access.organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY migration ON softteros_access.organizations TO :"owner_role" USING (true) WITH CHECK (true);
ALTER TABLE softteros_access.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE softteros_access.memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY migration ON softteros_access.memberships TO :"owner_role" USING (true) WITH CHECK (true);
ALTER TABLE softteros_access.membership_enquiry_capabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE softteros_access.membership_enquiry_capabilities FORCE ROW LEVEL SECURITY;
CREATE POLICY migration ON softteros_access.membership_enquiry_capabilities TO :"owner_role" USING (true) WITH CHECK (true);
ALTER TABLE softteros_access.organization_authority_fences ENABLE ROW LEVEL SECURITY;
ALTER TABLE softteros_access.organization_authority_fences FORCE ROW LEVEL SECURITY;
CREATE POLICY migration ON softteros_access.organization_authority_fences TO :"owner_role" USING (true) WITH CHECK (true);
ALTER TABLE softteros_access.enquiry_transition_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE softteros_access.enquiry_transition_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY migration ON softteros_access.enquiry_transition_grants TO :"owner_role" USING (true) WITH CHECK (true);
ALTER TABLE softteros_enquiries.enquiries ENABLE ROW LEVEL SECURITY;
ALTER TABLE softteros_enquiries.enquiries FORCE ROW LEVEL SECURITY;
CREATE POLICY migration ON softteros_enquiries.enquiries TO :"owner_role" USING (true) WITH CHECK (true);
ALTER TABLE softteros_enquiries.enquiry_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE softteros_enquiries.enquiry_events FORCE ROW LEVEL SECURITY;
CREATE POLICY migration ON softteros_enquiries.enquiry_events TO :"owner_role" USING (true) WITH CHECK (true);
ALTER TABLE softteros_enquiries.enquiry_command_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE softteros_enquiries.enquiry_command_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY migration ON softteros_enquiries.enquiry_command_receipts TO :"owner_role" USING (true) WITH CHECK (true);
CREATE POLICY tenant ON softteros_access.organizations TO :"runtime_role", :"writer_role", :"lock_role"
    USING (organization_id = softteros_access.context_organization())
    WITH CHECK (organization_id = softteros_access.context_organization());
CREATE POLICY tenant ON softteros_access.memberships TO :"runtime_role", :"writer_role", :"lock_role"
    USING (organization_id = softteros_access.context_organization())
    WITH CHECK (organization_id = softteros_access.context_organization());
CREATE POLICY tenant ON softteros_access.membership_enquiry_capabilities TO :"runtime_role", :"writer_role", :"lock_role"
    USING (organization_id = softteros_access.context_organization())
    WITH CHECK (organization_id = softteros_access.context_organization());
CREATE POLICY tenant ON softteros_access.organization_authority_fences TO :"runtime_role", :"writer_role", :"lock_role"
    USING (organization_id = softteros_access.context_organization())
    WITH CHECK (organization_id = softteros_access.context_organization());
CREATE POLICY tenant ON softteros_access.enquiry_transition_grants TO :"runtime_role", :"writer_role", :"lock_role"
    USING (organization_id = softteros_access.context_organization())
    WITH CHECK (organization_id = softteros_access.context_organization());
CREATE POLICY tenant_read ON softteros_enquiries.enquiries FOR SELECT TO :"runtime_role"
    USING (organization_id = softteros_access.context_organization());
CREATE POLICY tenant_insert ON softteros_enquiries.enquiries FOR INSERT TO :"runtime_role"
    WITH CHECK (organization_id = softteros_access.context_organization()
                AND created_by = softteros_access.context_actor());
CREATE POLICY tenant_update ON softteros_enquiries.enquiries FOR UPDATE TO :"runtime_role"
    USING (organization_id = softteros_access.context_organization())
    WITH CHECK (organization_id = softteros_access.context_organization());
CREATE POLICY tenant_read ON softteros_enquiries.enquiry_events FOR SELECT TO :"runtime_role"
    USING (organization_id = softteros_access.context_organization());
CREATE POLICY tenant_insert ON softteros_enquiries.enquiry_events FOR INSERT TO :"runtime_role"
    WITH CHECK (organization_id = softteros_access.context_organization()
                AND actor_id = softteros_access.context_actor());
CREATE POLICY tenant_read ON softteros_enquiries.enquiry_command_receipts FOR SELECT TO :"runtime_role"
    USING (organization_id = softteros_access.context_organization());
CREATE POLICY tenant_insert ON softteros_enquiries.enquiry_command_receipts FOR INSERT TO :"runtime_role"
    WITH CHECK (organization_id = softteros_access.context_organization()
                AND actor_id = softteros_access.context_actor());
CREATE POLICY tenant_update ON softteros_enquiries.enquiry_command_receipts FOR UPDATE TO :"runtime_role"
    USING (organization_id = softteros_access.context_organization())
    WITH CHECK (organization_id = softteros_access.context_organization() AND actor_id = softteros_access.context_actor());
ALTER TABLE softteros_access.actors ENABLE ROW LEVEL SECURITY;
ALTER TABLE softteros_access.actors FORCE ROW LEVEL SECURITY;
CREATE POLICY migration ON softteros_access.actors TO :"owner_role" USING (true) WITH CHECK (true);
CREATE POLICY actor ON softteros_access.actors TO :"runtime_role", :"writer_role", :"lock_role"
    USING (actor_id = softteros_access.context_actor())
    WITH CHECK (actor_id = softteros_access.context_actor());
ALTER TABLE softteros_access.actor_authority_fences ENABLE ROW LEVEL SECURITY;
ALTER TABLE softteros_access.actor_authority_fences FORCE ROW LEVEL SECURITY;
CREATE POLICY migration ON softteros_access.actor_authority_fences TO :"owner_role" USING (true) WITH CHECK (true);
CREATE POLICY actor ON softteros_access.actor_authority_fences TO :"runtime_role", :"writer_role", :"lock_role"
    USING (actor_id = softteros_access.context_actor())
    WITH CHECK (actor_id = softteros_access.context_actor());

-- Structural context existence/binding, not active permission or authentication.
-- The trusted writer must be able to provision new anchors before bindings exist.
CREATE FUNCTION softteros_access.valid_runtime_context() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM softteros_access.memberships m
        JOIN softteros_access.actors a ON a.actor_id=m.actor_id
        JOIN softteros_access.organizations o ON o.organization_id=m.organization_id
        WHERE m.actor_id=softteros_access.context_actor()
          AND m.organization_id=softteros_access.context_organization())
$$;
REVOKE ALL ON FUNCTION softteros_access.valid_runtime_context() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION softteros_access.valid_runtime_context() TO :"runtime_role", :"lock_role";

-- Restrictive policies also cover the global actor anchors/fences. Missing,
-- malformed, unknown, or unbound actor/tenant contexts cannot see runtime rows.
SELECT format('CREATE POLICY valid_context ON %I.%I AS RESTRICTIVE TO %I USING (softteros_access.valid_runtime_context()) WITH CHECK (softteros_access.valid_runtime_context())',
    n.nspname,c.relname,:'runtime_role')
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname IN ('softteros_access','softteros_enquiries') AND c.relkind='r'
\gexec

-- This function only locks already selected identity/tenant fences. It neither
-- authenticates the context nor grants an enquiry capability.
CREATE FUNCTION softteros_access.lock_current_authority(actor text, org text)
RETURNS TABLE (actor_revision bigint, organization_revision bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT softteros_access.valid_runtime_context()
       OR softteros_access.context_actor() IS NULL
       OR actor IS DISTINCT FROM softteros_access.context_actor()
       OR org IS DISTINCT FROM softteros_access.context_organization() THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'authority context unavailable';
    END IF;
    SELECT f.revision INTO actor_revision FROM softteros_access.actor_authority_fences f
        WHERE f.actor_id = actor FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'authority context unavailable';
    END IF;
    SELECT f.revision INTO organization_revision FROM softteros_access.organization_authority_fences f
        WHERE f.organization_id = org FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'authority context unavailable';
    END IF;
    RETURN NEXT;
END $$;
REVOKE ALL ON FUNCTION softteros_access.lock_current_authority(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION softteros_access.lock_current_authority(text, text) TO :"runtime_role";

-- Only the bootstrap administrator transfers the helper to its limited owner.
-- CREATE is temporary and is revoked in this same transaction.
GRANT CREATE ON SCHEMA softteros_access TO :"lock_role";
RESET ROLE;
ALTER FUNCTION softteros_access.lock_current_authority(text, text) OWNER TO :"lock_role";
REVOKE CREATE ON SCHEMA softteros_access FROM :"lock_role";
COMMIT;

