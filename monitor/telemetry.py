#!/usr/bin/env python3
import time
import ctypes as ct
import os
import sys
from pathlib import Path

for site_path in ("/usr/lib/python3/dist-packages", "/usr/local/lib/python3/dist-packages"):
    if os.path.isdir(site_path) and site_path not in sys.path:
        sys.path.insert(0, site_path)

from bcc import BPF

PROJECT_ROOT = Path(__file__).resolve().parent
BPF_FILE = PROJECT_ROOT / "bpf" / "simple_telemetry.bpf.c"

b = BPF(src_file=str(BPF_FILE))

probe_candidates = ["__x64_sys_execve", "sys_execve", "__arm64_sys_execve", "do_execveat_common"]
attached_probe = None
for probe in probe_candidates:
    try:
        b.attach_kprobe(event=probe, fn_name="trace_execve")
        attached_probe = probe
        break
    except Exception:
        continue

if attached_probe is None:
    raise RuntimeError(f"Unable to attach execve kprobe. Tried: {', '.join(probe_candidates)}")

print(f"Simple eBPF telemetry running on {attached_probe} (no vmlinux.h needed)!")
print("Watching process executions. Press Ctrl+C to stop.\n")

class Data(ct.Structure):
    _fields_ = [
        ("timestamp", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("comm", ct.c_char * 16)
    ]

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    ts = event.timestamp / 1_000_000_000.0
    comm = event.comm.decode('utf-8', errors='ignore').strip()
    print(f"[{ts:.3f}] PID {event.pid:6d} -> {comm}")

b["events"].open_perf_buffer(print_event)

try:
    while True:
        b.perf_buffer_poll()
        time.sleep(0.01)
except KeyboardInterrupt:
    print("\nStopped.")
