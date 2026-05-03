#!/usr/bin/env python3
"""
detect.py
Loads the trained model and runs live detection with fake anomaly injection.
When an anomaly is detected, writes scratch_repo/nos_alert.json so that
nos-watcher picks it up and invokes the ironclad-agent.
"""

import json
import time
import os
import sys
from pathlib import Path
import ctypes as ct
import threading
import joblib
import random

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent
WORKSPACE_ROOT = PROJECT_ROOT.parent
BPF_FILE = PROJECT_ROOT / "bpf" / "simple_telemetry.bpf.c"
MODEL_FILE = PROJECT_ROOT / "models" / "isolation_forest_model.pkl"
SCALER_FILE = PROJECT_ROOT / "models" / "scaler.pkl"
ALERT_FILE = WORKSPACE_ROOT / "scratch_repo" / "nos_alert.json"

FEATURES = [
    "cpu_percent",
    "mem_percent",
    "io_read_kbps",
    "io_write_kbps",
    "process_count",
    "syscall_rate_per_sec",
]

FEATURE_LABELS = {
    "cpu_percent": "CPU usage",
    "mem_percent": "Memory usage",
    "io_read_kbps": "Disk read I/O",
    "io_write_kbps": "Disk write I/O",
    "process_count": "Process count",
    "syscall_rate_per_sec": "Syscall rate",
}

eBPF_AVAILABLE = False
b = None
syscall_count = 0

if os.geteuid() == 0:
    for site_path in ("/usr/lib/python3/dist-packages", "/usr/local/lib/python3/dist-packages"):
        if os.path.isdir(site_path) and site_path not in sys.path:
            sys.path.insert(0, site_path)

    try:
        from bcc import BPF as BPFClass
        b = BPFClass(src_file=str(BPF_FILE))
        execve_fn = b.get_syscall_fnname("execve")
        b.attach_kprobe(event=execve_fn, fn_name="trace_execve")
        eBPF_AVAILABLE = True
        print("eBPF telemetry active")

        class Data(ct.Structure):
            _fields_ = [("timestamp", ct.c_ulonglong), ("pid", ct.c_uint), ("comm", ct.c_char * 16)]

        def count_event(cpu, data, size):
            global syscall_count
            syscall_count += 1

        b["events"].open_perf_buffer(count_event)

        def poll_ebpf():
            while True:
                try:
                    b.perf_buffer_poll(timeout=1000)
                except Exception:
                    pass

        threading.Thread(target=poll_ebpf, daemon=True).start()
    except Exception as exc:
        b = None
        print(f"eBPF attach failed: {exc}")
        print("Continuing with psutil-only (syscall_rate will be 0).")
else:
    print("eBPF disabled (not running as root)")
    print("Continuing with psutil-only features (syscall_rate_per_sec will remain 0).")
    print("For full eBPF telemetry, run:")
    print("  sudo python3 monitor/detect.py")

try:
    model = joblib.load(MODEL_FILE)
    scaler = joblib.load(SCALER_FILE)
    print("Model and scaler loaded successfully!")
except FileNotFoundError:
    print("Model not found! Please run: python3 monitor/train.py")
    exit(1)

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    print("psutil not available — using synthetic metrics only")
    PSUTIL_AVAILABLE = False


ANOMALY_PROB = 0.18

SEVERITY_THRESHOLDS = {
    "critical": -0.15,
    "warning": 0.0,
}


def classify_severity(score: float) -> str:
    if score < SEVERITY_THRESHOLDS["critical"]:
        return "critical"
    if score < SEVERITY_THRESHOLDS["warning"]:
        return "warning"
    return "normal"


def write_alert(dominant_feature: str, row: dict, score: float, severity: str) -> None:
    alert = {
        "process": "system",
        "metric": dominant_feature,
        "metric_label": FEATURE_LABELS.get(dominant_feature, dominant_feature),
        "observed_value": round(row.get(dominant_feature, 0), 2),
        "anomaly_score": round(score, 4),
        "severity": severity,
        "timestamp": time.time(),
        "ebpf_active": eBPF_AVAILABLE,
        "details": {
            "cpu_percent": round(row["cpu_percent"], 2),
            "mem_percent": round(row["mem_percent"], 2),
            "io_read_kbps": round(row["io_read_kbps"], 2),
            "io_write_kbps": round(row["io_write_kbps"], 2),
            "process_count": row["process_count"],
            "syscall_rate_per_sec": round(row["syscall_rate_per_sec"], 2),
        },
    }

    ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(ALERT_FILE, "w") as f:
        json.dump(alert, f, indent=2)
    print(f"   Alert written to {ALERT_FILE}")


def collect_metrics() -> dict:
    if PSUTIL_AVAILABLE:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_io_counters()
        io_read = max(0.0, disk.read_bytes / 1024 / 5)
        io_write = max(0.0, disk.write_bytes / 1024 / 5)
        proc_count = len(psutil.pids())
    else:
        cpu = random.uniform(1.0, 15.0)
        mem = random.uniform(50.0, 80.0)
        io_read = random.uniform(0.0, 50.0)
        io_write = random.uniform(0.0, 30.0)
        proc_count = random.randint(100, 300)

    global syscall_count
    syscall_rate = syscall_count / 5.0
    syscall_count = 0

    return {
        "timestamp": time.time(),
        "cpu_percent": cpu,
        "mem_percent": mem,
        "io_read_kbps": io_read,
        "io_write_kbps": io_write,
        "process_count": proc_count,
        "syscall_rate_per_sec": syscall_rate,
    }


def inject_anomaly(row: dict) -> str | None:
    if random.random() >= ANOMALY_PROB:
        return None

    anomaly_type = random.choice(["cpu", "syscall", "io", "mem"])
    if anomaly_type == "cpu":
        row["cpu_percent"] = random.uniform(82, 97)
        return "CPU Spike injected!"
    elif anomaly_type == "syscall":
        row["syscall_rate_per_sec"] = random.uniform(2200, 4800)
        return "Syscall Burst injected!"
    elif anomaly_type == "io":
        row["io_read_kbps"] = random.uniform(750, 1800)
        row["io_write_kbps"] = random.uniform(500, 1400)
        return "I/O Spike injected!"
    elif anomaly_type == "mem":
        row["mem_percent"] = random.uniform(85, 96)
        return "Memory Pressure Spike injected!"
    return None


print("\nLive Anomaly Detection Started (with demo spikes)")
print("Press Ctrl+C to stop\n")

try:
    while True:
        row = collect_metrics()

        injected = inject_anomaly(row)
        if injected:
            print(f"  [DEMO] {injected}")

        latest_df = pd.DataFrame([row])[FEATURES]
        scaled = scaler.transform(latest_df)

        scaled_vals = scaled[0]
        dominant_idx = int(abs(scaled_vals).argmax())
        dominant_feature = FEATURES[dominant_idx]
        dominant_z = scaled_vals[dominant_idx]

        prediction = model.predict(scaled)[0]
        score = model.decision_function(scaled)[0]

        if prediction == -1:
            severity = classify_severity(score)
            print(
                f"ANOMALY DETECTED! "
                f"Score:{score:.3f} "
                f"CPU:{row['cpu_percent']:5.1f}% "
                f"Mem:{row['mem_percent']:5.1f}% "
                f"Sys/s:{row['syscall_rate_per_sec']:7.1f} "
                f"Top:{dominant_feature} (z={dominant_z:+.2f}) "
                f"Severity:{severity}"
            )
            write_alert(dominant_feature, row, score, severity)
        else:
            print(
                f"   Normal         "
                f"Score:{score:.3f} "
                f"CPU:{row['cpu_percent']:5.1f}% "
                f"Mem:{row['mem_percent']:5.1f}% "
                f"Sys/s:{row['syscall_rate_per_sec']:7.1f}"
            )

        time.sleep(5)

except KeyboardInterrupt:
    print("\n\nAnomaly detection stopped.")
