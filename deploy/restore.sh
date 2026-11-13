#!/usr/bin/env bash
# Restore an OpenCM backup created by backup.sh.
# Usage: ./restore.sh <backup-dir> --yes
# WARNING: replaces the current database, file store and PKI.
set -euo pipefail
cd "$(dirname "$0")"

SRC="${1:?usage: restore.sh <backup-dir> --yes}"
[[ "${2:-}" == "--yes" ]] || { echo "Refusing to restore without --yes (this overwrites all data)."; exit 2; }
SRC="$(realpath "$SRC")"

( cd "$SRC" && sha256sum -c SHA256SUMS )

echo "==> Stopping application services"
docker compose stop server worker web proxy

echo "==> Restoring database"
docker compose up -d postgres
until docker compose exec -T postgres pg_isready -U opencm -d opencm >/dev/null 2>&1; do sleep 1; done
docker compose exec -T postgres psql -U opencm -d postgres -c "DROP DATABASE IF EXISTS opencm WITH (FORCE);"
docker compose exec -T postgres psql -U opencm -d postgres -c "CREATE DATABASE opencm OWNER opencm;"
docker compose exec -T postgres pg_restore -U opencm -d opencm --no-owner < "$SRC/db.dump"

echo "==> Restoring file store and PKI"
for vol in files pki; do
  docker run --rm -v "opencm_${vol}:/dst" -v "$SRC:/src:ro" alpine:3 \
    sh -c "find /dst -mindepth 1 -delete && tar -xzf /src/${vol}.tar.gz -C /dst"
done

echo "==> Starting OpenCM"
docker compose up -d
echo "Restore complete."
