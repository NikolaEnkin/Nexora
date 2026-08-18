-- Local/fake Compose credentials only. Production roles come from deployment secret management.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nexora_migrator') THEN
    CREATE ROLE nexora_migrator LOGIN PASSWORD 'local-migrator-only'
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nexora_runtime') THEN
    CREATE ROLE nexora_runtime LOGIN PASSWORD 'local-runtime-only'
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nexora_rls_guard') THEN
    CREATE ROLE nexora_rls_guard NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT BYPASSRLS;
  END IF;
END
$$;

GRANT nexora_rls_guard TO nexora_migrator;

ALTER DATABASE nexora OWNER TO nexora_migrator;
ALTER SCHEMA public OWNER TO nexora_migrator;
GRANT CONNECT ON DATABASE nexora TO nexora_runtime;
