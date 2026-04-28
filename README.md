# 🔒 Ironclad Agent

> **A zero-trust WebAssembly runtime for autonomous AI agents** — where every line of LLM-generated code runs in a cryptographically audited sandbox, never on your host machine.

[![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![arXiv](https://img.shields.io/badge/arXiv-2405.xxxxx-red.svg)](https://arxiv.org)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)

---

## 🎯 What Is This?

An AI code-execution agent that **physically cannot escape its sandbox**. The LLM generates Python scripts. Those scripts run inside a WebAssembly jail with:

- ✅ **No network access** — outbound calls blocked at runtime
- ✅ **No filesystem escape** — reads/writes confined to `/sandbox`
- ✅ **CPU budgeted** — infinite loops killed in milliseconds
- ✅ **Tamper-proof audit log** — SHA-256 hashed execution provenance
- ✅ **4.26x faster than Docker** — thanks to Wasmtime caching

**The demo:** Ask the agent to solve a task. It writes code, runs it, returns the result. Show the audit log proving what executed. Explain that the code physically could not touch the network or filesystem. That's the pitch that gets you hired.

---

## 🚀 Quick Start

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

# Option 2: Start the AI agent
cargo run -p ironclad-agent -- "Calculate: 5 + 3 * 2"

# If you built release binaries already, you can also run:
# ./target/release/ironclad-agent "Calculate: 5 + 3 * 2"

# Give it a task, e.g., "Calculate the 10th Fibonacci number"
# Watch it generate code, execute it safely, and return the result
```

---

## 📊 Performance Benchmarks

The **4.26x speedup over Docker** comes from eliminating redundant JIT compilation via Wasmtime's integrated cache.

```text
Scenario: Execute Python 3.12 interpreter 100 times

│ Runtime         │ Median   │ P95       │ P99       │ Min      │
├─────────────────┼──────────┼───────────┼───────────┼──────────┤
│ Docker (alpine) │ 778 ms   │ 791 ms    │ 805 ms    │ 765 ms   │
│ Ironclad w/ cache│ 182 ms   │ 199 ms    │ 206 ms    │ 167 ms   │
│ **Speedup**     │ **4.26x**│ **3.97x** │ **3.91x** │ **4.58x**│
└─────────────────┴──────────┴───────────┴───────────┴──────────┘

Memory overhead per execution:
  • Docker container:      50–100 MB
  • Ironclad instance:     5–10 MB
  • Savings:              ~90%
```

**What changed to achieve this:** See [WASM Caching Internals](docs/8_WASM_CACHING_INTERNALS.md) for the technical deep-dive on why caching was critical.

### Run Benchmarks Yourself

```bash
# Warm-start benchmark (100 iterations with 5 warmup runs)
python tests/benchmarks/run_benchmark.py --iterations 100 --warmup 5

# Output includes P95, P99, min/max, and Docker comparison
```

---

## 🏗️ Architecture

### System Design

```
┌────────────────────────────────────────────────────────────┐
│                  AI Agent Layer (Python)                   │
│                                                            │
│  User Task → LangGraph (ReAct) → execute_secure_code()    │
└────────────────────┬──────────────────────────────────────┘
                     │ subprocess call
                     ▼
┌────────────────────────────────────────────────────────────┐
│              Ironclad Runtime Layer (Rust)                 │
│                                                            │
│  1. Hash script (SHA-256)                                 │
│  2. Load WASM module (cached via Wasmtime)                │
│  3. Configure sandbox:                                    │
│     • Filesystem: only /sandbox read/write               │
│     • Network: blocked                                   │
│     • Fuel budget: CPU instruction limit                 │
│  4. Execute Python interpreter (in WASM)                 │
│  5. Log execution: hash + timestamp → audit.log          │
│  6. Return stdout/stderr                                 │
└────────────────────────────────────────────────────────────┘
                     ▲
        Wasmtime Engine (JIT compiled code cache)
        [Cached compilation = 15ms per run]
```

### Key Components

| Component            | Purpose                                    | Language                |
| -------------------- | ------------------------------------------ | ----------------------- |
| **ironclad-runtime** | Sandbox engine; compiles/runs WASM modules | Rust                    |
| **agent/**           | ReAct reasoning loop + code generation     | Python (LangGraph)      |
| **python.wasm**      | Python 3.12 compiled to WASM               | WASM (from VMware Labs) |
| **Audit Log**        | Tamper-proof execution history             | JSON + SHA-256          |

---

## 🔐 Security Model

### What's Guaranteed

```
┌─────────────────────────────────────────────────────┐
│          Threat Model & Mitigations                 │
├─────────────────────────────────────────────────────┤
│ Threat: Out-of-bounds memory access                │
│ → Blocked by: WASM memory bounds checks             │
│ → Verified at compile time (Cranelift)            │
│                                                    │
│ Threat: Network escape                             │
│ → Blocked by: WASI context (no socket capability) │
│ → Enforced at runtime                             │
│                                                    │
│ Threat: Infinite loop (DoS)                        │
│ → Blocked by: Fuel-based instruction metering      │
│ → Kills at: 1M fuel units ≈ 100ms                │
│                                                    │
│ Threat: Filesystem escape                          │
│ → Blocked by: chroot-like /sandbox isolation       │
│ → Enforced at file syscall boundary               │
│                                                    │
│ Threat: Execution tampering                        │
│ → Prevented by: SHA-256 audit log + timestamps     │
│ → Verifiable offline                              │
└─────────────────────────────────────────────────────┘
```

### Audit Log Verification

Every execution produces an immutable record:

```bash
# View audit log
cat audit.log | jq '.[] | {script_hash, timestamp, exit_code}'

# Verify a specific execution
./target/release/ironclad-runtime --verify abc123def... script.py
# Output: "✓ VERIFIED — hash matches audit log entry #42"
```

---

## 📖 Documentation

| Document                                                        | Content                                    |
| --------------------------------------------------------------- | ------------------------------------------ |
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

## 💡 Usage Examples

### Example 1: Simple Code Execution

```python
from pathlib import Path
import subprocess

# Write a Python script to the sandbox
script = Path(".sandbox/calc.py")
script.write_text("""
result = sum(range(1, 101))
print(f"Sum of 1-100: {result}")
""")

# Execute it securely
proc = subprocess.run(
    ["./target/release/ironclad-runtime", str(script)],
    capture_output=True,
    text=True,
)

print(proc.stdout)  # "Sum of 1-100: 5050"
```

### Example 2: Using the AI Agent

```bash
cargo run -p ironclad-agent -- "Find all prime numbers less than 100"

# Agent prompt:
# "Find all prime numbers less than 100"

# Agent will:
# 1. Think about how to solve this
# 2. Generate Python code
# 3. Execute in sandbox (secure)
# 4. Analyze output
# 5. Return answer with audit proof
```

### Example 3: Detect Security Violations

```python
script = Path(".sandbox/escape.py")
script.write_text("""
import os
os.system("cat /etc/passwd")
""")

# Run it
proc = subprocess.run(
    ["./target/release/ironclad-runtime", str(script)],
    capture_output=True,
    text=True,
)

# Result: Permission denied (caught by WASI)
print(proc.stderr)  # "os.system: Permission denied"

# Audit log shows the attempt was made but contained
```

---

## 🛠️ Development

### Project Structure

```
ironclad-agent/
├── agent/                  # Python agent code (LangGraph)
│   ├── main.py            # Entry point
│   └── Cargo.toml         # Rust workspace member
├── src/                   # Rust runtime
│   └── main.rs            # Wasmtime initialization + sandbox setup
├── tests/                 # Test suite
│   ├── smoke/             # Smoke tests
│   └── benchmarks/        # Performance benchmarks
├── docs/                  # Complete documentation
├── python-3.12.0.wasm    # Python interpreter (prebuilt)
├── Cargo.toml            # Rust workspace root
├── pyproject.toml        # Python dependencies
└── Makefile              # Convenience build commands
```

### Building from Source

```bash
# Full build (Rust + Python)
make build

# Just Rust runtime
cargo build --release -p ironclad-runtime

# Just run tests
make test

# Benchmarks only
make bench

# Clean
make clean
```

### Enabling Features

The cache feature is already enabled in `Cargo.toml`. To rebuild without it:

```bash
cargo build --release --no-default-features
# Note: Performance will be ~10x worse due to JIT recompilation
```

---

## 🧪 Testing

### Run The Scripts

Build the runtime first, then run each script against the sandbox binary. On Windows, use the `.exe` path; on Unix-like systems, use the release binary.

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

Windows equivalents:

```powershell
cargo build --release
.\target\release\ironclad-runtime.exe tests\smoke\scripts\test_normal.py
.\target\release\ironclad-runtime.exe tests\smoke\scripts\test_network.py
.\target\release\ironclad-runtime.exe tests\smoke\scripts\test_filesystem_escape.py
.\target\release\ironclad-runtime.exe tests\smoke\scripts\test_infinite.py
```

If you want to run everything in one pass, use the smoke harness:

```bash
python tests/smoke/run_smoke.py
```

The runtime appends JSONL entries to `audit.log` for successful executions, so you can verify what ran after the scripts finish.

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
.\target\release\ironclad-runtime tests\smoke\scripts\my_test.py
```

---

## 📈 Performance Tuning

### Fuel Budget

Adjust CPU limit by modifying fuel in `src/main.rs`:

```rust
// Current: 1M fuel ≈ 100ms
store.add_fuel(1_000_000)?;

// More generous: 5M fuel ≈ 500ms
store.add_fuel(5_000_000)?;

// Very strict: 100K fuel ≈ 10ms
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

## 🐛 Troubleshooting

### Issue: "Wasmtime cache unavailable"

```
⚠️ WARN: Wasmtime cache unavailable, continuing without cache
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
- Modify WASI context to allow other paths (not recommended for security)

### Issue: Benchmarks show different numbers

Caching behavior varies based on:

- Whether cache was warmed up (run multiple times)
- Disk speed (SSD vs HDD)
- System load (close other programs)
- CPU thermal throttling

Always run with `--warmup 5` flag and take median over 100+ iterations.

---

## 🔬 Research & Publications

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

## 🤝 Contributing

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
3. Make your changes and test: `make test`
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

## 📋 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

In short: Use it for anything, anywhere. Just give attribution.

---

## 🙏 Acknowledgments

- **Wasmtime** team for the JIT compiler and caching infrastructure
- **LangGraph** for the ReAct agent framework
- **VMware Labs** for the Python-to-WASM compilation
- **Rust community** for making systems programming accessible

---

## 📞 Support & Community

- **Issues & Bug Reports:** [GitHub Issues](https://github.com/yourusername/ironclad-agent/issues)
- **Discussions & Q&A:** [GitHub Discussions](https://github.com/yourusername/ironclad-agent/discussions)
- **Email:** your.email@example.com

---

## 🎬 Getting Started Checklist

- [ ] Read [docs/0_README.md](docs/0_README.md) for project overview
- [ ] Follow [Quick Start](#-quick-start) above
- [ ] Run `make test` to verify installation
- [ ] Try a benchmark: `python tests/benchmarks/run_benchmark.py --iterations 10`
- [ ] Read [docs/4_Architecture.md](docs/4_Architecture.md) to understand the internals
- [ ] Examine [docs/8_WASM_CACHING_INTERNALS.md](docs/8_WASM_CACHING_INTERNALS.md) for CS-level deep dive

---

**Made with ❤️ by the Ironclad team**

⭐ If this helps you, consider starring the repo!
