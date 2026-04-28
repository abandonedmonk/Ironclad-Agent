.PHONY: all build run smoke clean

# ─── Build ────────────────────────────────────────────────────────────────────

all: build

build:
	@echo "🦀 Building Rust workspace..."
	cargo build --release
	@echo "✅ Build complete."

# ─── Run ──────────────────────────────────────────────────────────────────────

## Run the Rust runtime binary
run:
	@echo "🦀 Running ironclad-runtime..."
	./target/release/ironclad-runtime

## Run the ReAct agent
agent:
	@echo "🤖 Running ironclad-agent..."
	./target/release/ironclad-agent

## Run smoke tests (normal, network, filesystem, fuel)
smoke:
	@echo "🧪 Running smoke test suite..."
	python tests/smoke/run_smoke.py

# ─── Clean ────────────────────────────────────────────────────────────────────

clean:
	@echo "🧹 Cleaning build artifacts..."
	cargo clean
