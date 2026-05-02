#!/usr/bin/env bash
# Window 2: Live hash-chain viewer for the CEO demo.
# Run: bash display/audit_display.sh
watch -n1 'python3 -c "
import sys, json, pathlib
path = pathlib.Path(\"scratch_repo/nos_audit.jsonl\")
if not path.exists():
    print(\"Waiting for audit log...\")
    sys.exit(0)
lines = path.read_text().strip().splitlines()[-8:]
for l in lines:
    e = json.loads(l)
    print(f\"[{e[chr(39)]seq[chr(39)]}] {e[chr(39)]event_type[chr(39)]:25} hash:{e[chr(39)]entry_hash[chr(39)][:14]}...\")
"'
