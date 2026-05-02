#!/usr/bin/env python3
"""Window 1: Pretty-prints the nos_audit.jsonl stream for the CEO demo.
Run: tail -f scratch_repo/nos_audit.jsonl | python3 display/pipeline_display.py
"""
import sys, json, pathlib

path = pathlib.Path("scratch_repo/nos_audit.jsonl")
if not path.exists():
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        continue

    t = e.get("event_type", "")
    d = e.get("detail", {})

    if t == "ANOMALY_DETECTED":
        print(f"\n🔴 ANOMALY DETECTED at {e['timestamp']}")
        print(f"   Metric  : {d.get('metric')} = {d.get('observed_value')}")
        print(f"   Score   : {d.get('anomaly_score')} | Severity: {str(d.get('severity','')).upper()}")

    elif t == "AGENT_REASONING":
        print(f"🧠 {d.get('step', d)}")

    elif t == "SCRIPT_SUBMITTED":
        print(f"\n📋 SCRIPT SUBMITTED TO SANDBOX")
        print(f"   Requires: {d.get('requires')}")
        print(f"   Purpose : {d.get('purpose')}")
        print(f"   Hash    : {e.get('entry_hash','')[:16]}...")

    elif t == "SANDBOX_RESULT":
        print(f"⚙️  SANDBOX EXECUTED — {d.get('runtime_ms')}ms | Exit: {d.get('exit_code')}")

    elif t == "AGENT_SUMMARY":
        print(f"\n✅ DIAGNOSIS:")
        print(f"   {d.get('summary')}")
        print(f"\n{'─'*60}")
