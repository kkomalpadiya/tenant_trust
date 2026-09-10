#!/bin/sh
set -eu

psql -v ON_ERROR_STOP=1 <<'SQL'
CREATE SCHEMA IF NOT EXISTS platform;
CREATE TABLE IF NOT EXISTS platform.schema_migrations (
  migration_name text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
);
SQL

for migration in /migrations/*.sql; do
  [ -f "$migration" ] || continue
  migration_name=$(basename "$migration")

  case "$migration_name" in
    *[!A-Za-z0-9._-]*)
      echo "Invalid migration filename: $migration_name" >&2
      exit 1
      ;;
  esac

  applied=$(psql -v ON_ERROR_STOP=1 -Atqc \
    "SELECT 1 FROM platform.schema_migrations WHERE migration_name = '$migration_name'")

  if [ "$applied" = "1" ]; then
    echo "Already applied: $migration_name"
    continue
  fi

  echo "Applying: $migration_name"
  psql -v ON_ERROR_STOP=1 -1 -f "$migration"
  psql -v ON_ERROR_STOP=1 -c \
    "INSERT INTO platform.schema_migrations (migration_name) VALUES ('$migration_name')"
done
