#!/usr/bin/env bash
# Backup of OpenCM: PostgreSQL dump + file store + PKI (CA/certificates).
# Usage: ./backup.sh [target-dir]        (default: ./backups)
set -euo pipefail
cd "$(dirname "$0")"

TARGET="${1:-./backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="$TARGET/opencm-$STAMP"
mkdir -p "$DEST"
chmod 700 "$DEST"

echo "==> Database dump"
docker compose exec -T postgres pg_dump -U opencm -d opencm -Fc > "$DEST/db.dump"

echo "==> File store and PKI volumes"
for vol in files pki; do
  docker run --rm \
    -v "opencm_${vol}:/src:ro" \
    -v "$(realpath "$DEST"):/dst" \
    alpine:3 tar -czf "/dst/${vol}.tar.gz" -C /src .
done

( cd "$DEST" && sha256sum db.dump files.tar.gz pki.tar.gz > SHA256SUMS )
echo "==> Backup written to $DEST"
echo "    Contains the CA private key – store it encrypted and access-restricted."
