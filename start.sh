#!/bin/bash

echo "starting..."

# Don’t let this hang forever
freshclam --stdout || echo "freshclam failed (ignored)"

mkdir -p /run/clamav
chown -R clamav:clamav /run/clamav || true

clamd --foreground &

echo "clam started"

exec python3 src/app_v5.py