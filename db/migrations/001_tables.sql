-- SQL foundation only. Run through scripts/test-postgres.sh in a disposable database.
BEGIN;
SET LOCAL ROLE :"owner_role";
SET LOCAL search_path = pg_catalog, pg_temp;
SET LOCAL timezone = 'UTC';
CREATE SCHEMA softteros_access AUTHORIZATION :"owner_role";
CREATE SCHEMA softteros_enquiries AUTHORIZATION :"owner_role";
REVOKE ALL ON SCHEMA softteros_access, softteros_enquiries FROM PUBLIC;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE DOMAIN softteros_access.identifier AS text COLLATE "C"
    CHECK (VALUE ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$');
-- PostgreSQL has already converted these values to microseconds. The future
-- adapter must reject unsupported source precision BEFORE binding a value.
CREATE DOMAIN softteros_access.instant AS timestamptz
    CHECK (isfinite(VALUE) AND VALUE > TIMESTAMPTZ '0001-01-01 00:00:00+00'
           AND VALUE < TIMESTAMPTZ '10000-01-01 00:00:00+00');

CREATE FUNCTION softteros_access.context_actor() RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp
AS $$
    SELECT CASE WHEN current_setting('softteros.actor_id', true) COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
                     AND current_setting('softteros.organization_id', true) COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
                THEN current_setting('softteros.actor_id', true) END
$$;
CREATE FUNCTION softteros_access.context_organization() RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp
AS $$
    SELECT CASE WHEN softteros_access.context_actor() IS NOT NULL
                THEN current_setting('softteros.organization_id', true) END
$$;
REVOKE ALL ON FUNCTION softteros_access.context_actor(), softteros_access.context_organization() FROM PUBLIC;

CREATE TABLE softteros_access.actors (
    actor_id softteros_access.identifier PRIMARY KEY
);
CREATE TABLE softteros_access.organizations (
    organization_id softteros_access.identifier PRIMARY KEY
);
CREATE TABLE softteros_access.memberships (
    organization_id softteros_access.identifier NOT NULL REFERENCES softteros_access.organizations,
    membership_id softteros_access.identifier NOT NULL,
    actor_id softteros_access.identifier NOT NULL REFERENCES softteros_access.actors,
    active boolean NOT NULL,
    revoked boolean NOT NULL,
    valid_from softteros_access.instant NOT NULL,
    valid_until softteros_access.instant NOT NULL,
    PRIMARY KEY (organization_id, membership_id),
    UNIQUE (organization_id, membership_id, actor_id),
    CHECK (valid_from < valid_until)
);
CREATE INDEX memberships_actor ON softteros_access.memberships(actor_id, organization_id, membership_id);
CREATE TABLE softteros_access.membership_enquiry_capabilities (
    organization_id softteros_access.identifier NOT NULL,
    membership_id softteros_access.identifier NOT NULL,
    capability text COLLATE "C" NOT NULL CHECK (capability IN ('enquiries.create','enquiries.review','enquiries.qualify')),
    PRIMARY KEY (organization_id, membership_id, capability),
    FOREIGN KEY (organization_id, membership_id) REFERENCES softteros_access.memberships
);
CREATE TABLE softteros_access.actor_authority_fences (
    actor_id softteros_access.identifier PRIMARY KEY REFERENCES softteros_access.actors,
    revision bigint NOT NULL CHECK (revision > 0)
);
CREATE TABLE softteros_access.organization_authority_fences (
    organization_id softteros_access.identifier PRIMARY KEY REFERENCES softteros_access.organizations,
    revision bigint NOT NULL CHECK (revision > 0)
);

CREATE TABLE softteros_enquiries.enquiries (
    organization_id softteros_access.identifier NOT NULL REFERENCES softteros_access.organizations,
    enquiry_id softteros_access.identifier NOT NULL,
    contact_name text NOT NULL CHECK (char_length(contact_name) BETWEEN 1 AND 120),
    contact_email text NOT NULL CHECK (octet_length(contact_email) BETWEEN 1 AND 254),
    destination text NOT NULL CHECK (char_length(destination) BETWEEN 1 AND 200),
    traveller_count integer NOT NULL CHECK (traveller_count BETWEEN 1 AND 99),
    travel_start date,
    travel_end date,
    state text COLLATE "C" NOT NULL,
    created_by softteros_access.identifier NOT NULL,
    creator_membership_id softteros_access.identifier NOT NULL,
    created_at softteros_access.instant NOT NULL,
    assignee_membership_id softteros_access.identifier,
    version bigint NOT NULL,
    last_changed_at softteros_access.instant NOT NULL,
    PRIMARY KEY (organization_id, enquiry_id),
    FOREIGN KEY (organization_id, creator_membership_id, created_by)
        REFERENCES softteros_access.memberships(organization_id, membership_id, actor_id),
    FOREIGN KEY (organization_id, assignee_membership_id)
        REFERENCES softteros_access.memberships(organization_id, membership_id),
    CONSTRAINT enquiry_dates CHECK (
        (travel_start IS NULL AND travel_end IS NULL) OR
        (travel_start IS NOT NULL AND travel_end IS NOT NULL AND
         travel_start >= DATE '0001-01-01' AND travel_end < DATE '10000-01-01' AND
         travel_start <= travel_end)),
    CONSTRAINT enquiry_shape CHECK (
        (state = 'New' AND version = 1 AND assignee_membership_id IS NULL AND last_changed_at = created_at) OR
        (state = 'Under review' AND version = 2 AND assignee_membership_id IS NOT NULL) OR
        (state = 'Qualified' AND version = 3 AND assignee_membership_id IS NOT NULL)),
    CHECK (last_changed_at >= created_at)
);
CREATE INDEX enquiries_creator ON softteros_enquiries.enquiries(organization_id, creator_membership_id, created_by);
CREATE INDEX enquiries_assignee ON softteros_enquiries.enquiries(organization_id, assignee_membership_id);

CREATE TABLE softteros_access.enquiry_transition_grants (
    organization_id softteros_access.identifier NOT NULL,
    grant_id softteros_access.identifier NOT NULL,
    actor_id softteros_access.identifier NOT NULL,
    membership_id softteros_access.identifier NOT NULL,
    enquiry_id softteros_access.identifier NOT NULL,
    capability text COLLATE "C" NOT NULL CHECK (capability IN ('enquiries.review','enquiries.qualify')),
    active boolean NOT NULL,
    revoked boolean NOT NULL,
    valid_from softteros_access.instant NOT NULL,
    valid_until softteros_access.instant NOT NULL,
    PRIMARY KEY (organization_id, grant_id),
    UNIQUE (organization_id, grant_id, enquiry_id, actor_id, membership_id, capability),
    FOREIGN KEY (organization_id, membership_id, actor_id)
        REFERENCES softteros_access.memberships(organization_id, membership_id, actor_id),
    FOREIGN KEY (organization_id, enquiry_id) REFERENCES softteros_enquiries.enquiries,
    CHECK (valid_from < valid_until)
);
CREATE INDEX grants_member ON softteros_access.enquiry_transition_grants(organization_id, membership_id, actor_id);
CREATE INDEX grants_enquiry ON softteros_access.enquiry_transition_grants(organization_id, enquiry_id);

CREATE TABLE softteros_enquiries.enquiry_events (
    organization_id softteros_access.identifier NOT NULL,
    event_id softteros_access.identifier NOT NULL,
    enquiry_id softteros_access.identifier NOT NULL,
    request_key softteros_access.identifier NOT NULL,
    active_organization_id softteros_access.identifier NOT NULL,
    actor_id softteros_access.identifier NOT NULL,
    membership_id softteros_access.identifier NOT NULL,
    grant_id softteros_access.identifier,
    action text COLLATE "C" NOT NULL,
    capability text COLLATE "C" NOT NULL,
    outcome text NOT NULL CHECK (outcome = 'success'),
    actor_authority_revision bigint NOT NULL CHECK (actor_authority_revision > 0),
    organization_authority_revision bigint NOT NULL CHECK (organization_authority_revision > 0),
    previous_state text COLLATE "C",
    new_state text COLLATE "C" NOT NULL,
    previous_assignee_membership_id softteros_access.identifier,
    assignee_membership_id softteros_access.identifier,
    previous_version bigint,
    resulting_version bigint NOT NULL,
    at softteros_access.instant NOT NULL,
    PRIMARY KEY (organization_id, event_id),
    UNIQUE (organization_id, enquiry_id, resulting_version),
    UNIQUE (organization_id, membership_id, request_key),
    UNIQUE (organization_id, event_id, enquiry_id, resulting_version, actor_id, membership_id, action),
    FOREIGN KEY (organization_id, enquiry_id) REFERENCES softteros_enquiries.enquiries,
    FOREIGN KEY (organization_id, membership_id, actor_id)
        REFERENCES softteros_access.memberships(organization_id, membership_id, actor_id),
    FOREIGN KEY (organization_id, assignee_membership_id) REFERENCES softteros_access.memberships,
    FOREIGN KEY (organization_id, previous_assignee_membership_id) REFERENCES softteros_access.memberships,
    FOREIGN KEY (organization_id, grant_id, enquiry_id, actor_id, membership_id, capability)
        REFERENCES softteros_access.enquiry_transition_grants(organization_id, grant_id, enquiry_id, actor_id, membership_id, capability),
    CHECK (active_organization_id = organization_id),
    CONSTRAINT event_shape CHECK (
        (action = 'enquiry.created' AND capability = 'enquiries.create' AND grant_id IS NULL
         AND previous_state IS NULL AND new_state = 'New'
         AND previous_version IS NULL AND resulting_version = 1
         AND previous_assignee_membership_id IS NULL AND assignee_membership_id IS NULL) OR
        (action = 'enquiry.review_started' AND capability = 'enquiries.review' AND grant_id IS NOT NULL
         AND previous_state IS NOT NULL AND previous_state = 'New' AND new_state = 'Under review'
         AND previous_version IS NOT NULL AND previous_version = 1 AND resulting_version = 2
         AND previous_assignee_membership_id IS NULL AND assignee_membership_id = membership_id) OR
        (action = 'enquiry.qualified' AND capability = 'enquiries.qualify' AND grant_id IS NOT NULL
         AND previous_state IS NOT NULL AND previous_state = 'Under review' AND new_state = 'Qualified'
         AND previous_version IS NOT NULL AND previous_version = 2 AND resulting_version = 3
         AND previous_assignee_membership_id = membership_id AND assignee_membership_id = membership_id)),
    -- Explicit null checks prevent SQL's UNKNOWN from satisfying event_shape.
    CHECK (resulting_version = 1 OR assignee_membership_id IS NOT NULL),
    CHECK (resulting_version <> 3 OR previous_assignee_membership_id IS NOT NULL)
);
CREATE INDEX events_member ON softteros_enquiries.enquiry_events(organization_id, membership_id, actor_id);
CREATE INDEX events_grant ON softteros_enquiries.enquiry_events(organization_id, grant_id, enquiry_id, actor_id, membership_id, capability);
CREATE INDEX events_assignee ON softteros_enquiries.enquiry_events(organization_id, assignee_membership_id);
CREATE INDEX events_previous_assignee ON softteros_enquiries.enquiry_events(organization_id, previous_assignee_membership_id);

CREATE TABLE softteros_enquiries.enquiry_command_receipts (
    organization_id softteros_access.identifier NOT NULL,
    membership_id softteros_access.identifier NOT NULL,
    request_key softteros_access.identifier NOT NULL,
    actor_id softteros_access.identifier NOT NULL,
    command text COLLATE "C" NOT NULL CHECK (command IN ('enquiry.created','enquiry.review_started','enquiry.qualified')),
    expected_version bigint NOT NULL CHECK (
        (command = 'enquiry.created' AND expected_version = 0) OR
        (command = 'enquiry.review_started' AND expected_version = 1) OR
        (command = 'enquiry.qualified' AND expected_version = 2)),
    fingerprint_version smallint NOT NULL CHECK (fingerprint_version = 1),
    fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
    enquiry_id softteros_access.identifier,
    event_id softteros_access.identifier,
    resulting_version bigint,
    completed boolean NOT NULL DEFAULT false,
    completed_at softteros_access.instant,
    PRIMARY KEY (organization_id, membership_id, request_key),
    UNIQUE (organization_id, event_id),
    FOREIGN KEY (organization_id, membership_id, actor_id)
        REFERENCES softteros_access.memberships(organization_id, membership_id, actor_id),
    CONSTRAINT receipt_event_binding FOREIGN KEY (organization_id, event_id, enquiry_id, resulting_version, actor_id, membership_id, command)
        REFERENCES softteros_enquiries.enquiry_events(organization_id, event_id, enquiry_id, resulting_version, actor_id, membership_id, action)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT receipt_completion CHECK (NOT completed OR
        (enquiry_id IS NOT NULL AND event_id IS NOT NULL AND resulting_version IS NOT NULL
         AND completed_at IS NOT NULL AND resulting_version = expected_version + 1))
);
CREATE INDEX receipts_event ON softteros_enquiries.enquiry_command_receipts(organization_id, event_id, enquiry_id, resulting_version, actor_id, membership_id, command);
CREATE INDEX receipts_member ON softteros_enquiries.enquiry_command_receipts(organization_id, membership_id, actor_id);
ALTER TABLE softteros_enquiries.enquiry_events ADD CONSTRAINT event_receipt
    FOREIGN KEY (organization_id, membership_id, request_key)
    REFERENCES softteros_enquiries.enquiry_command_receipts
    DEFERRABLE INITIALLY DEFERRED;
COMMIT;

