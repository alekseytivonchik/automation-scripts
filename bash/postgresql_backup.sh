#!/usr/bin/env bash
set -euo pipefail

echo "=== PostgreSQL SQL backup script ==="

read -rp "PostgreSQL host [localhost]: " PGHOST
PGHOST=${PGHOST:-localhost}

read -rp "PostgreSQL port [5432]: " PGPORT
PGPORT=${PGPORT:-5432}

read -rp "PostgreSQL user: " PGUSER

read -rsp "PostgreSQL password: " PGPASSWORD
echo

read -rp "Database names separated by space: " DBS

read -rp "Backup directory [./pg_backups]: " BACKUP_DIR
BACKUP_DIR=${BACKUP_DIR:-./pg_backups}

mkdir -p "$BACKUP_DIR"

export PGPASSWORD

DATE=$(date +"%Y-%m-%d_%H-%M-%S")

for DB in $DBS; do
  echo "Backing up database: $DB"

  OUT_FILE="${BACKUP_DIR}/${DB}_${DATE}.sql"

  pg_dump \
    --host="$PGHOST" \
    --port="$PGPORT" \
    --username="$PGUSER" \
    --dbname="$DB" \
    --format=p \
    --file="$OUT_FILE" \
    --no-password

#  gzip "$OUT_FILE"

  echo "Done: ${OUT_FILE}"
done

unset PGPASSWORD

echo "All backups completed."
