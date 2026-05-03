#!/usr/bin/env python3
"""
train.py
Trains Isolation Forest from existing telemetry logs or live eBPF + psutil data.

Default behavior:
- If data.txt exists and has parseable rows, train from that immediately.
- Otherwise collect live telemetry and then train.
"""

import argparse
import ctypes as ct
import os
import re
import sys
import threading
import time
from pathlib import Path

import joblib
import pandas as pd
import psutil
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


FEATURES = [
    "cpu_percent",
    "mem_percent",
    "io_read_kbps",
    "io_write_kbps",
    "process_count",
    "syscall_rate_per_sec",
]

PROJECT_ROOT = Path(__file__).resolve().parent
BPF_FILE = PROJECT_ROOT / "bpf" / "simple_telemetry.bpf.c"
LOG_FILE = PROJECT_ROOT / "data" / "data.txt"
DATA_CSV_FILE = PROJECT_ROOT / "data" / "telemetry_data.csv"
MODEL_FILE = PROJECT_ROOT / "models" / "isolation_forest_model.pkl"
SCALER_FILE = PROJECT_ROOT / "models" / "scaler.pkl"


def save_dataframe(df: pd.DataFrame) -> None:
    DATA_CSV_FILE.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(DATA_CSV_FILE, index=False)
    print(f"Saved {len(df)} samples to {DATA_CSV_FILE}")


def train_and_save(df: pd.DataFrame) -> None:
    for col in FEATURES:
        if col not in df.columns:
            df[col] = 0.0

    X = df[FEATURES].fillna(0.0)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(n_estimators=150, contamination=0.05, random_state=42)
    model.fit(X_scaled)

    MODEL_FILE.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_FILE)
    joblib.dump(scaler, SCALER_FILE)

    print("\nTraining complete")
    print(f"Model saved to {MODEL_FILE}")
    print(f"Scaler saved to {SCALER_FILE}")


def parse_terminal_log(log_path: str) -> pd.DataFrame:
    pattern = re.compile(
        r"^\[(?P<time>\d{2}:\d{2}:\d{2})\]\s+CPU:\s*(?P<cpu>[0-9.]+)%\s+Mem:\s*(?P<mem>[0-9.]+)%\s+"
        r"Syscalls/s:\s*(?P<syscalls>[0-9.]+)\s+Samples:\s*(?P<sample>\d+)"
    )

    rows = []
    base_ts = time.time()

    with open(log_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            match = pattern.match(line.strip())
            if not match:
                continue

            rows.append(
                {
                    "timestamp": base_ts + (idx * 5),
                    "cpu_percent": float(match.group("cpu")),
                    "mem_percent": float(match.group("mem")),
                    "io_read_kbps": 0.0,
                    "io_write_kbps": 0.0,
                    "process_count": 0.0,
                    "syscall_rate_per_sec": float(match.group("syscalls")),
                }
            )

    return pd.DataFrame(rows)


def get_bpf_class():
    for site_path in ("/usr/lib/python3/dist-packages", "/usr/local/lib/python3/dist-packages"):
        if os.path.isdir(site_path) and site_path not in sys.path:
            sys.path.insert(0, site_path)

    try:
        from bcc import BPF
    except ImportError as exc:
        raise ImportError(
            "Unable to import BPF from bcc. On Ubuntu 22.04 install: "
            "sudo apt-get install python3-bpfcc libbpfcc libbpfcc-dev bpfcc-tools"
        ) from exc

    return BPF


def collect_live_data(target_samples: int) -> pd.DataFrame:
    BPF = get_bpf_class()

    b = BPF(src_file=str(BPF_FILE))
    execve_fn = b.get_syscall_fnname("execve")
    b.attach_kprobe(event=execve_fn, fn_name="trace_execve")

    class Data(ct.Structure):
        _fields_ = [("timestamp", ct.c_ulonglong), ("pid", ct.c_uint), ("comm", ct.c_char * 16)]

    _ = Data
    syscall_count = 0

    def count_event(cpu, data, size):
        nonlocal syscall_count
        syscall_count += 1

    b["events"].open_perf_buffer(count_event)

    def poll_ebpf():
        while True:
            try:
                b.perf_buffer_poll(timeout=1000)
            except Exception:
                pass

    threading.Thread(target=poll_ebpf, daemon=True).start()

    data_buffer = []
    print("Training mode: collecting live telemetry for model training")
    print(f"Collecting {target_samples} samples. Press Ctrl+C to stop.\n")

    while len(data_buffer) < target_samples:
        cpu = psutil.cpu_percent(interval=0.2)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_io_counters()
        io_read = max(0.0, disk.read_bytes / 1024 / 5)
        io_write = max(0.0, disk.write_bytes / 1024 / 5)
        proc_count = len(psutil.pids())

        syscall_rate = syscall_count / 5.0
        syscall_count = 0

        row = {
            "timestamp": time.time(),
            "cpu_percent": cpu,
            "mem_percent": mem,
            "io_read_kbps": io_read,
            "io_write_kbps": io_write,
            "process_count": proc_count,
            "syscall_rate_per_sec": syscall_rate,
        }

        data_buffer.append(row)

        print(
            f"[{time.strftime('%H:%M:%S')}] CPU:{cpu:5.1f}%  Mem:{mem:5.1f}%  "
            f"Syscalls/s:{syscall_rate:6.1f}  Samples: {len(data_buffer)}"
        )
        time.sleep(5)

    return pd.DataFrame(data_buffer)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train anomaly model from existing or live telemetry")
    parser.add_argument("--log-file", default=str(LOG_FILE), help="Path to terminal telemetry log")
    parser.add_argument("--live-only", action="store_true", help="Ignore log file and collect live data")
    parser.add_argument("--samples", type=int, default=300, help="Live samples to collect")
    args = parser.parse_args()

    try:
        if not args.live_only and os.path.exists(args.log_file):
            df = parse_terminal_log(args.log_file)
            if not df.empty:
                print(f"Using existing telemetry log from {args.log_file} ({len(df)} rows)")
                save_dataframe(df)
                train_and_save(df)
                return
            print(f"Log file {args.log_file} found but no parseable rows. Falling back to live collection.")

        df = collect_live_data(args.samples)
        save_dataframe(df)
        train_and_save(df)

    except KeyboardInterrupt:
        print("\nTraining stopped by user.")


if __name__ == "__main__":
    main()
