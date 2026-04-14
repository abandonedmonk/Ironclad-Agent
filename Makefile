.PHONY: all build run rust python smoke clean

# ─── Build ────────────────────────────────────────────────────────────────────

## Build both the Rust runtime and verify the Python env
all: build

build: rust-build
	@echo "✅ Full build complete."

rust-build:
	@echo "🦀 Building Rust runtime..."
	cargo build --release

# ─── Run ──────────────────────────────────────────────────────────────────────

## Run both: Rust runtime, then the LangGraph agent
run: rust-run python-run

## Run only the Rust binary
rust-run:
	@echo "🦀 Running ironclad-runtime..."
	./target/release/ironclad-runtime

## Run only the Python agent
python-run:
	@echo "🐍 Running LangGraph agent..."
	uv run python agent/main.py

## Run smoke tests (normal, network, filesystem, fuel)
smoke:
	@echo "🧪 Running smoke test suite..."
	python tests/smoke/run_smoke.py

# ─── Dev ──────────────────────────────────────────────────────────────────────

## Run Python without rebuilding Rust (fast iteration)
dev:
	@echo "🐍 Starting agent (dev mode)..."
	uv run python agent/main.py

# ─── Clean ────────────────────────────────────────────────────────────────────

clean:
	@echo "🧹 Cleaning build artifacts..."
	cargo clean
