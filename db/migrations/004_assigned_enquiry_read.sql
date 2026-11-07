BEGIN;
SET LOCAL ROLE :"owner_role";
SET LOCAL search_path = pg_catalog, pg_temp;

ALTER TABLE softteros_access.membership_enquiry_capabilities
    DROP CONSTRAINT membership_enquiry_capabilities_capability_check,
    ADD CONSTRAINT membership_enquiry_capabilities_capability_check
        CHECK (capability IN ('enquiries.create','enquiries.review','enquiries.qualify','enquiries.read'));

COMMIT;
