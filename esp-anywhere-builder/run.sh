#!/usr/bin/env bash
set -euo pipefail
umask 077
install -d -m 0700 /data/keys /data/secrets /data/jobs /tmp/esp-anywhere-builder
exec python3 /app/app.py
