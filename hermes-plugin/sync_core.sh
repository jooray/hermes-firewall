#!/bin/sh
# Vendor the stdlib-only parts of hermes_firewall into the plugin, so the plugin needs nothing
# installed in Hermes' venv (Pillow, already there, is used for image metadata only).
set -e
cd "$(dirname "$0")"
SRC=../firewall/src/hermes_firewall
DST=prompt-firewall/core
mkdir -p "$DST"
for f in extract.py policy.py questions.py jev_detector.py; do cp "$SRC/$f" "$DST/$f"; done
cp "$SRC/policy-jev.json" "$DST/policy-jev.json" 2>/dev/null || echo "note: no policy-jev.json yet"
printf '"""Vendored from firewall/src/hermes_firewall by sync_core.sh. Do not edit here."""\n' > "$DST/__init__.py"
echo "synced: $(ls $DST | tr '\n' ' ')"
