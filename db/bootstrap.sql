-- All names are supplied by the disposable harness; collisions fail atomically.
BEGIN;
CREATE ROLE :"owner_role" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE :"runtime_role" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE :"writer_role" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE :"lock_role" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
COMMENT ON ROLE :"owner_role" IS :'marker';
COMMENT ON ROLE :"runtime_role" IS :'marker';
COMMENT ON ROLE :"writer_role" IS :'marker';
COMMENT ON ROLE :"lock_role" IS :'marker';
ALTER ROLE :"runtime_role" SET statement_timeout = '10s';
ALTER ROLE :"runtime_role" SET lock_timeout = '500ms';
ALTER ROLE :"runtime_role" SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE :"runtime_role" SET transaction_timeout = '20s';
ALTER ROLE :"writer_role" SET statement_timeout = '10s';
ALTER ROLE :"writer_role" SET lock_timeout = '500ms';
ALTER ROLE :"writer_role" SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE :"writer_role" SET transaction_timeout = '20s';
COMMIT;

