\set ON_ERROR_STOP on

-- The second disposable database has exactly migrations 001 through 003 here.
INSERT INTO softteros_access.actors VALUES ('upgrade-actor');
INSERT INTO softteros_access.organizations VALUES ('upgrade-org');
INSERT INTO softteros_access.memberships VALUES
    ('upgrade-org','upgrade-member','upgrade-actor',true,false,'2000-01-01+00','9999-01-01+00');
INSERT INTO softteros_access.membership_enquiry_capabilities VALUES
    ('upgrade-org','upgrade-member','enquiries.create'),
    ('upgrade-org','upgrade-member','enquiries.review'),
    ('upgrade-org','upgrade-member','enquiries.qualify');

DO $$
DECLARE failed_constraint text;
BEGIN
    BEGIN
        INSERT INTO softteros_access.membership_enquiry_capabilities
            VALUES ('upgrade-org','upgrade-member','enquiries.read');
    EXCEPTION WHEN check_violation THEN
        GET STACKED DIAGNOSTICS failed_constraint = CONSTRAINT_NAME;
    END;
    IF failed_constraint IS DISTINCT FROM 'membership_enquiry_capabilities_capability_check' THEN
        RAISE EXCEPTION 'expected the baseline capability allowlist to deny enquiries.read';
    END IF;
END $$;

CREATE TEMP TABLE read_upgrade_entitlements AS
    TABLE softteros_access.membership_enquiry_capabilities;
CREATE TEMP VIEW read_upgrade_security AS
SELECT jsonb_build_object('acl', c.relacl, 'rls', c.relrowsecurity, 'forced', c.relforcerowsecurity,
    'policies', (SELECT jsonb_agg(to_jsonb(p) ORDER BY p.policyname)
        FROM pg_catalog.pg_policies p
        WHERE p.schemaname='softteros_access' AND p.tablename='membership_enquiry_capabilities')) AS facts
FROM pg_catalog.pg_class c
WHERE c.oid='softteros_access.membership_enquiry_capabilities'::regclass;
CREATE TEMP TABLE read_upgrade_security_before AS TABLE read_upgrade_security;

\ir ../migrations/004_assigned_enquiry_read.sql

DO $$
BEGIN
    IF EXISTS (
        (TABLE softteros_access.membership_enquiry_capabilities EXCEPT TABLE read_upgrade_entitlements)
        UNION ALL
        (TABLE read_upgrade_entitlements EXCEPT TABLE softteros_access.membership_enquiry_capabilities)
    ) THEN
        RAISE EXCEPTION 'upgrade changed existing entitlements or granted enquiries.read automatically';
    END IF;
    IF (SELECT facts FROM read_upgrade_security) IS DISTINCT FROM
        (SELECT facts FROM read_upgrade_security_before) THEN
        RAISE EXCEPTION 'upgrade changed capability table privileges or row security';
    END IF;
END $$;
