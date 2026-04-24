#!/usr/bin/env bash
set -euo pipefail

OUT="${1:-server.pem}"

openssl req -x509 -newkey rsa:2048 -keyout "$OUT" -out "$OUT" \
  -days 365 -nodes -subj "/CN=localhost" 2>/dev/null

echo "[+] Self-signed cert written to $OUT"
