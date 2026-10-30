-- A separate psql connection proves the failure occurs at COMMIT, not an
-- unrelated earlier statement. The caller must observe REACHED_COMMIT.
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL ROLE :"runtime_role";
SELECT set_config('softteros.actor_id','actor-2',true),set_config('softteros.organization_id','org-1',true);
\if :pending_receipt
INSERT INTO softteros_enquiries.enquiry_command_receipts
 (organization_id,membership_id,request_key,actor_id,command,expected_version,fingerprint_version,fingerprint)
 VALUES ('org-1','member-3','commit-invalid','actor-2','enquiry.created',0,1,decode(repeat('ab',32),'hex'));
\else
INSERT INTO softteros_enquiries.enquiries VALUES
 ('org-1','commit-invalid','Contact','contact@example.com','Norway',1,NULL,NULL,'New','actor-2','member-3',
  '2026-10-29+00',NULL,1,'2026-10-29+00');
\if :missing_receipt
INSERT INTO softteros_enquiries.enquiry_events
 (organization_id,event_id,enquiry_id,request_key,active_organization_id,actor_id,membership_id,
  action,capability,outcome,actor_authority_revision,organization_authority_revision,new_state,resulting_version,at)
 VALUES ('org-1','commit-invalid-event','commit-invalid','commit-invalid','org-1','actor-2','member-3',
  'enquiry.created','enquiries.create','success',1,1,'New',1,'2026-10-29+00');
\endif
\endif
\echo REACHED_COMMIT
COMMIT;

