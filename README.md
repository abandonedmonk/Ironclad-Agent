# Ironclad Agent

> **A zero-trust WebAssembly runtime for autonomous AI agents** — where every line of LLM-generated code runs in a cryptographically audited sandbox, never on your host machine.

[![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![arXiv](https://img.shields.io/badge/arXiv-2405.xxxxx-red.svg)](https://arxiv.org)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)

---

## What Is This?

An AI code-execution agent that **physically cannot escape its sandbox**. The LLM generates Python scripts. Those scripts run inside a WebAssembly jail with:

- **No network access** — outbound calls blocked at runtime
- **No filesystem escape** — reads/writes confined to `/sandbox`
- **CPU budgeted** — infinite loops killed in milliseconds
- **Tamper-proof audit log** — SHA-256 hashed execution provenance
- **4.26x faster than Docker** — thanks to Wasmtime caching
- **Autonomous monitoring** — eBPF anomaly detection triggers agent diagnosis without human input

**The demo:** An eBPF probe detects anomalous system behavior. A watcher hands the alert to an LLM agent. The agent writes diagnostic Python, runs it in the WASM sandbox, and returns findings with a tamper-proof audit log — all without human intervention. That's the pitch that gets you hired.

---

## Quick Start

### Prerequisites

- **Rust 1.70+** ([install rustup](https://rustup.rs/))
- **Python 3.12+**
- **make** (optional, but recommended)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ironclad-agent.git
cd ironclad-agent

# Build the Rust runtime (with compilation cache enabled)
cargo build --release

# Set up Python environment
python -m venv .venv
source .venv/bin/activate  # or `.venv\Scripts\activate` on Windows

# Install Python dependencies
pip install -r requirements.txt
```

### Run Your First Sandboxed Execution

```bash
# Option 1: Run a simple test script
./target/release/ironclad-runtime tests/smoke/scripts/hello.py

# Option 2: Start the AI agent with a task
./target/release/ironclad-agent "Calculate the 10th Fibonacci number"

# Option 3: Full autonomous pipeline (anomaly detection -> agent -> sandbox)
make demo

# Stop the pipeline
make demo-stop
```

### One-Command Demo Pipeline

```bash
make demo
```

This starts the full autonomous loop:

1. **Anomaly detector** (`monitor/detect.py`) — eBPF telemetry + Isolation Forest, writes alert on anomaly
2. **nos-watcher** — polls for alerts, invokes the AI agent
3. **ironclad-agent** — LLM generates pure-Python diagnostic code
4. **ironclad-runtime** — executes the code in a WASM sandbox

Logs stream to the console. Stop with `Ctrl+C` or `make demo-stop`.

---

## Performance Benchmarks

The **4.26x speedup over Docker** comes from eliminating redundant JIT compilation via Wasmtime's integrated cache.

```text
Scenario: Execute Python 3.12 interpreter 100 times

| Runtime          | Median   | P95       | P99       | Min      |
|------------------|----------|-----------|-----------|----------|
| Docker (alpine)  | 778 ms   | 791 ms    | 805 ms    | 765 ms   |
| Ironclad w/ cache| 182 ms   | 199 ms    | 206 ms    | 167 ms   |
| **Speedup**      | **4.26x**| **3.97x** | **3.91x** | **4.58x**|

Memory overhead per execution:
  Docker container:      50-100 MB
  Ironclad instance:     5-10 MB
  Savings:              ~90%
```

**What changed to achieve this:** See [WASM Caching Internals](docs/8_WASM_CACHING_INTERNALS.md) for the technical deep-dive on why caching was critical.

### Run Benchmarks Yourself

```bash
# Warm-start benchmark (100 iterations with 5 warmup runs)
python tests/benchmarks/run_benchmark.py --iterations 100 --warmup 5

# Output includes P95, P99, min/max, and Docker comparison
```

---

## Architecture

### System Design

```
+---------------------------------------------------------------+
|                  Monitoring Layer (Python)                     |
|                                                                |
|  eBPF probes (execve, tcp) -> Isolation Forest -> anomaly alert|
+----------------------------+-----------------------------------+
                             | writes scratch_repo/nos_alert.json
                             v
+---------------------------------------------------------------+
|                  Watcher Layer (Rust)                          |
|                                                                |
|  nos-watcher polls for alerts -> invokes ironclad-agent        |
+----------------------------+-----------------------------------+
                             | spawns agent process
                             v
+---------------------------------------------------------------+
|                  AI Agent Layer (Rust + Cohere)                |
|                                                                |
|  User Task / Alert -> ReAct loop -> generate Python code       |
+----------------------------+-----------------------------------+
                             | subprocess call
                             v
+---------------------------------------------------------------+
|              Ironclad Runtime Layer (Rust/WASM)                |
|                                                                |
|  1. Hash script (SHA-256)                                     |
|  2. Load WASM module (cached via Wasmtime)                    |
|  3. Configure sandbox:                                        |
|     - Filesystem: /sandbox read/write, /proc read-only        |
|     - Network: blocked                                        |
|     - Fuel budget: CPU instruction limit                      |
|  4. Execute Python interpreter (in WASM)                      |
|  5. Log execution: hash + timestamp -> nos_audit.jsonl        |
|  6. Return stdout/stderr                                      |
+---------------------------------------------------------------+
                             ^
         Wasmtime Engine (JIT compiled code cache)
         [Cached compilation = 15ms per run]
```

### Key Components

| Component            | Purpose                                    | Language                |
|----------------------|--------------------------------------------|-------------------------|
| **ironclad-runtime** | Sandbox engine; compiles/runs WASM modules | Rust                    |
| **ironclad-agent**   | ReAct reasoning loop + code generation     | Rust (Cohere LLM)       |
| **nos-watcher**      | Polls for anomaly alerts, invokes agent    | Rust                    |
| **monitor/**         | eBPF telemetry + anomaly detection         | Python (scikit-learn)   |
| **python.wasm**      | Python 3.12 compiled to WASM               | WASM (from VMware Labs) |
| **Audit Log**        | Hash-chained execution history             | JSONL + SHA-256         |

### Pipeline Flow

```
detect.py (anomaly detected)
  -> writes scratch_repo/nos_alert.json
    -> nos-watcher (polls every 2s)
      -> invokes ironclad-agent
        -> LLM generates pure-Python diagnostic script
          -> ironclad-runtime (WASM sandbox)
            -> script reads /proc/ files (read-only)
            -> returns results + audit log entry
```

---

## Security Model

### What's Guaranteed

```
+-----------------------------------------------------+
|          Threat Model & Mitigations                  |
+-----------------------------------------------------+
| Threat: Out-of-bounds memory access                 |
| -> Blocked by: WASM memory bounds checks            |
| -> Verified at compile time (Cranelift)             |
|                                                      |
| Threat: Network escape                              |
| -> Blocked by: WASI context (no socket capability)  |
| -> Enforced at runtime                              |
|                                                      |
| Threat: Infinite loop (DoS)                         |
| -> Blocked by: Fuel-based instruction metering      |
| -> Kills at: 1M fuel units = ~100ms                |
|                                                      |
| Threat: Filesystem escape                           |
| -> Blocked by: chroot-like /sandbox isolation       |
| -> /proc/ mounted read-only for diagnostics         |
| -> Enforced at file syscall boundary                |
|                                                      |
| Threat: Execution tampering                         |
| -> Prevented by: SHA-256 audit log + timestamps    |
| -> Verifiable offline                               |
+-----------------------------------------------------+
```

### Audit Log Verification

Every execution produces an immutable record:

```bash
# View the hash-chained audit trail
cat scratch_repo/nos_audit.jsonl | python3 -m json.tool

# Verify a specific execution
./target/release/ironclad-runtime --verify abc123def... script.py
```

---

## Documentation

| Document                                                        | Content                                    |
|-----------------------------------------------------------------|--------------------------------------------|
| [0_README.md](docs/0_README.md)                                 | Project overview and pitch                 |
| [1_Roadmap.md](docs/1_Roadmap.md)                               | Build steps + learning prerequisites       |
| [2_Tech_Stack.md](docs/2_Tech_Stack.md)                         | Every layer with tradeoff analysis         |
| [3_MVP.md](docs/3_MVP.md)                                       | Scope definition + success criteria        |
| [4_Architecture.md](docs/4_Architecture.md)                     | Data flow diagrams + runtime details       |
| [5_Tauri_Overlap.md](docs/5_Tauri_Overlap.md)                   | Reusable components for desktop apps       |
| [6_Research_Paper.md](docs/6_Research_Paper.md)                 | Full whitepaper draft (arXiv ready)        |
| [7_Glossary.md](docs/7_Glossary.md)                             | Technical term definitions                 |
| [8_WASM_Caching_Internals.md](docs/8_WASM_CACHING_INTERNALS.md) | Deep dive: why caching matters + internals |

---

## Usage Examples

### Example 1: Simple Code Execution

```python
from pathlib import Path
import subprocess

script = Path(".sandbox/calc.py")
script.write_text("""
result = sum(range(1, 101))
print(f"Sum of 1-100: {result}")
""")

proc = subprocess.run(
    ["./target/release/ironclad-runtime", str(script)],
    capture_output=True,
    text=True,
)

print(proc.stdout)  # "Sum of 1-100: 5050"
```

### Example 2: Using the AI Agent

```bash
./target/release/ironclad-agent "Find all prime numbers less than 100"

# Agent will:
# 1. Think about how to solve this
# 2. Generate Python code
# 3. Execute in sandbox (secure)
# 4. Analyze output
# 5. Return answer with audit proof
```

### Example 3: Requesting Packages (Pure-Python Wheels Only)

```python
# REQUIRES: python-dateutil, six
from dateutil.parser import parse

print(parse("2022-01-01").strftime("%Y-%m-%d"))
```

The runtime resolves package hints before execution, mounts approved pure-Python wheels into the sandbox, and returns structured JSON if a package is rejected. Native-extension packages such as `numpy` are blocked and reported with alternatives. Packages like `pyyaml` are rejected because they only publish platform-specific or source distributions.

### Example 4: Detect Security Violations

```python
script = Path(".sandbox/escape.py")
script.write_text("""
import os
os.system("cat /etc/passwd")
""")

proc = subprocess.run(
    ["./target/release/ironclad-runtime", str(script)],
    capture_output=True,
    text=True,
)

# Result: Permission denied (caught by WASI)
print(proc.stderr)  # "os.system: Permission denied"
```

### Example 5: System Diagnostics via /proc/

```python
# /proc/ is mounted read-only inside the sandbox
# No need for psutil or other C-extension packages
with open("/proc/meminfo") as f:
    for line in f:
        if line.startswith("MemTotal") or line.startswith("MemAvailable"):
            print(line.strip())

with open("/proc/loadavg") as f:
    print("Load average:", f.read().strip())
```

---

## Demo Commands

### Full Autonomous Pipeline

```bash
# Build + start the complete loop: eBPF anomaly -> watcher -> agent -> sandbox
make demo

# Stop all pipeline processes
make demo-stop
```

### Individual Pipeline Components

```bash
# Anomaly detection only (writes alerts to scratch_repo/nos_alert.json)
make demo-detect

# Watcher only (polls for alerts, invokes agent)
make demo-watch

# Retrain the Isolation Forest model from monitor/data/
make train
```

### Standalone Agent

```bash
# Direct agent invocation with a task
./target/release/ironclad-agent "Calculate the 10th Fibonacci number"

# Agent with external packages (pure-Python only)
./target/release/ironclad-agent "Write Python that uses python-dateutil and six to parse '2022-01-01' and print it. Use REQUIRES comments only."
```

### Demo 1: Date Parsing with External Libraries

```bash
./target/release/ironclad-runtime --packages python-dateutil test.py
```

Test script `test.py`:

```python
from dateutil.parser import parse
# REQUIRES: python-dateutil, six
print(parse("2022-01-01").strftime("%Y-%m-%d"))
```

### Demo 2: Requests Library (No Network Calls)

```bash
./target/release/ironclad-runtime --packages requests test.py
```

Test script `test.py`:

```python
import requests
import click
# REQUIRES: requests, urllib3, idna, certifi, charset-normalizer, click

@click.command()
def main():
    click.echo(requests.__version__)

if __name__ == "__main__":
    main()
```

### Demo 3: System Diagnostics via /proc/

```bash
./target/release/ironclad-runtime test.py
```

Test script `test.py`:

```python
with open("/proc/meminfo") as f:
    for line in f:
        if line.startswith("MemTotal") or line.startswith("MemAvailable"):
            print(line.strip())
```

The `/proc/` filesystem is mounted read-only inside the sandbox, so diagnostic scripts can read system metrics without needing C-extension packages like `psutil`.

### Verify Execution Audit Log

```bash
# View the hash-chained audit trail
cat scratch_repo/nos_audit.jsonl | python3 -m json.tool

# Verify a specific execution hash
./target/release/ironclad-runtime --verify <script_hash> test.py
```

---

## Development

### Project Structure

```
ironclad-agent/
+-- agent/                  # AI agent (ReAct loop + code generation)
|   +-- src/main.rs        # Cohere LLM integration, tool execution
|   +-- Cargo.toml         # Rust workspace member
+-- nos-watcher/            # Alert polling + agent invocation
|   +-- src/main.rs        # Polls scratch_repo/nos_alert.json
|   +-- Cargo.toml         # Rust workspace member
+-- src/                    # Ironclad runtime (WASM sandbox engine)
|   +-- main.rs            # Wasmtime initialization + sandbox setup
|   +-- audit.rs           # Hash-chained audit log
|   +-- crypto.rs          # SHA-256 hashing
|   +-- packages.rs        # Pure-Python wheel resolver
|   +-- verify.rs          # Audit log verification
+-- monitor/                # eBPF telemetry + anomaly detection
|   +-- bpf/               # eBPF kernel probes
|   |   +-- simple_telemetry.bpf.c   # BCC-compatible probe
|   |   +-- telemetry.bpf.c          # libbpf-style probe
|   +-- models/            # Pre-trained ML models
|   |   +-- isolation_forest_model.pkl
|   |   +-- scaler.pkl
|   +-- data/              # Training data
|   |   +-- telemetry_data.csv
|   |   +-- data.txt
|   +-- detect.py          # Live anomaly detection (writes alerts)
|   +-- train.py           # Model training
|   +-- telemetry.py       # Standalone eBPF telemetry viewer
+-- scratch_repo/           # Runtime handshake zone
|   +-- nos_alert.json     # Alert written by detect.py
|   +-- nos_audit.jsonl    # Hash-chained audit log
+-- display/                # Audit visualization
|   +-- audit_display.sh
|   +-- pipeline_display.py
+-- tests/                  # Test suite
|   +-- smoke/             # Smoke tests
|   +-- benchmarks/        # Performance benchmarks
+-- docs/                   # Complete documentation
+-- python-3.12.0.wasm     # Python interpreter (prebuilt)
+-- Cargo.toml             # Rust workspace root
+-- Makefile               # Build + demo commands
```

### Building from Source

```bash
# Full build (all workspace binaries)
make build

# Individual binaries
cargo build --release -p ironclad-runtime
cargo build --release -p ironclad-agent
cargo build --release -p nos-watcher

# Run tests
make smoke

# Clean
make clean
```

### Monitoring Setup

The anomaly detection pipeline uses eBPF and scikit-learn:

```bash
# Install Python dependencies
pip install scikit-learn joblib pandas psutil

# Retrain the model (optional — pre-trained model included)
make train

# Run detection standalone (requires root for eBPF)
sudo python3 monitor/detect.py

# Run without root (skips BPF, uses simulated metrics)
python3 monitor/detect.py
```

### Environment Variables

| Variable          | Purpose                              | Required |
|-------------------|--------------------------------------|----------|
| `COHERE_API_KEY`  | API key for the LLM agent            | Yes      |
| `NOS_DEBUG`       | Set to `1` for verbose agent output  | No       |
| `WASMTIME_CACHE_DIR` | Custom Wasmtime cache directory   | No       |

---

## Testing

### Run The Scripts

Build the runtime first, then run each script against the sandbox binary:

```bash
# Build once
cargo build --release

# Normal script
./target/release/ironclad-runtime tests/smoke/scripts/test_normal.py

# Network-isolation script
./target/release/ironclad-runtime tests/smoke/scripts/test_network.py

# Filesystem-isolation script
./target/release/ironclad-runtime tests/smoke/scripts/test_filesystem_escape.py

# Fuel-exhaustion script
./target/release/ironclad-runtime tests/smoke/scripts/test_infinite.py
```

If you want to run everything in one pass, use the smoke harness:

```bash
python tests/smoke/run_smoke.py
```

The runtime appends JSONL entries to `scratch_repo/nos_audit.jsonl` for successful executions, so you can verify what ran after the scripts finish.

### Smoke Tests

```bash
# Run all smoke tests
python tests/smoke/run_smoke.py

# Expected output:
# test_hello .......................... PASS
# test_isolation_filesystem ........... PASS
# test_isolation_network ............. PASS
# test_fuel_limit .................... PASS
# test_audit_log ..................... PASS
```

### Adding Your Own Test

```python
# tests/smoke/scripts/my_test.py
print("Hello from test!")
exit(0)
```

```bash
# Run it
./target/release/ironclad-runtime tests/smoke/scripts/my_test.py
```

---

## Performance Tuning

### Fuel Budget

Adjust CPU limit by modifying fuel in `src/main.rs`:

```rust
// Current: 1M fuel = ~100ms
store.add_fuel(1_000_000)?;

// More generous: 5M fuel = ~500ms
store.add_fuel(5_000_000)?;

// Very strict: 100K fuel = ~10ms
store.add_fuel(100_000)?;
```

### Memory Allocation

Modify WASI context memory size:

```rust
// Current: 2 pages = 128 KB
// Change in src/main.rs where WasiCtx is created
```

### Cache Configuration

Cache location and size are configurable via environment:

```bash
# Use custom cache directory
export WASMTIME_CACHE_DIR=/custom/path

# Run with cache logging
RUST_LOG=debug ./target/release/ironclad-runtime script.py
```

---

## Troubleshooting

### Issue: "Wasmtime cache unavailable"

```
WARN: Wasmtime cache unavailable, continuing without cache
```

**Solution:** The cache feature may not be compiled. Rebuild:

```bash
cargo clean
cargo build --release
```

### Issue: "Out of fuel"

```
Error: Instance doesn't have any fuel to execute
```

**Solution:** Your script exceeded the fuel budget. Either:

- Increase fuel: modify `store.add_fuel()` in `src/main.rs`
- Optimize your script to use fewer instructions

### Issue: "Permission denied" (filesystem)

Your script tried to access outside `/sandbox`. This is intentional. Either:

- Use `.sandbox/` directory only
- Read `/proc/` for system metrics (mounted read-only)
- Modify WASI context to allow other paths (not recommended for security)

### Issue: eBPF import errors

`monitor/detect.py` requires `sudo` for eBPF. Without root, it automatically skips BPF and uses simulated metrics. For real eBPF telemetry:

```bash
sudo python3 monitor/detect.py
```

### Issue: Benchmarks show different numbers

Caching behavior varies based on:

- Whether cache was warmed up (run multiple times)
- Disk speed (SSD vs HDD)
- System load (close other programs)
- CPU thermal throttling

Always run with `--warmup 5` flag and take median over 100+ iterations.

---

## Research & Publications

### Citation

If you use Ironclad in research or production, please cite:

```bibtex
@software{ironclad2025,
  title={Ironclad: WebAssembly Sandboxing for Autonomous AI Agents},
  author={Your Name},
  year={2025},
  url={https://github.com/yourusername/ironclad-agent}
}
```

### Whitepaper

Full research paper draft available at [docs/6_Research_Paper.md](docs/6_Research_Paper.md).

**Target venues:** arXiv (cs.CR or cs.AI), IEEE S&P, USENIX Security, NeurIPS Safety Workshop

---

## Contributing

We welcome contributions! Here's how:

### Setup Development Environment

```bash
# Clone and install development tools
git clone https://github.com/yourusername/ironclad-agent.git
cd ironclad-agent
cargo install cargo-fmt cargo-clippy
pip install black ruff pytest
```

### Code Style

- **Rust:** `cargo fmt` + `cargo clippy`
- **Python:** `black` + `ruff`

### Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes and test: `make smoke`
4. Commit with clear messages: `git commit -am "feat: add X"`
5. Push and open a PR

### What We're Looking For

- Bug fixes
- Performance improvements
- New WASI capabilities
- Better error messages
- Documentation improvements
- Additional test cases

### What We Can't Merge

- Changes that weaken security guarantees
- Additions that compromise the audit log
- Dependencies that break offline capability

---

## License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

In short: Use it for anything, anywhere. Just give attribution.

---

## Acknowledgments

- **Wasmtime** team for the JIT compiler and caching infrastructure
- **Cohere** for the LLM API
- **VMware Labs** for the Python-to-WASM compilation
- **Rust community** for making systems programming accessible

---

## Getting Started Checklist

- [ ] Follow [Quick Start](#quick-start) above
- [ ] Run `make smoke` to verify installation
- [ ] Run `make demo` to see the full autonomous pipeline
- [ ] Try a benchmark: `python tests/benchmarks/run_benchmark.py --iterations 10`
- [ ] Read [docs/4_Architecture.md](docs/4_Architecture.md) to understand the internals
- [ ] Examine [docs/8_WASM_CACHING_INTERNALS.md](docs/8_WASM_CACHING_INTERNALS.md) for CS-level deep dive
