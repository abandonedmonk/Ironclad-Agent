.PHONY: all build run smoke clean demo demo-watch demo-detect train demo-stop

# ─── Build ────────────────────────────────────────────────────────────────────

all: build

build:
	@echo "Building Rust workspace..."
	cargo build --release --workspace
	@echo "Build complete."

# ─── Run ──────────────────────────────────────────────────────────────────────

run:
	@echo "Running ironclad-runtime..."
	./target/release/ironclad-runtime

agent:
	@echo "Running ironclad-agent..."
	./target/release/ironclad-agent

smoke:
	@echo "Running smoke test suite..."
	python tests/smoke/run_smoke.py

# ─── Monitor ──────────────────────────────────────────────────────────────────

train:
	@echo "Training anomaly detection model..."
	python3 monitor/train.py

demo-detect:
	@echo "Starting anomaly detection (with demo spikes)..."
	@mkdir -p scratch_repo
	python3 -u monitor/detect.py

demo-watch:
	@echo "Starting nos-watcher (polling for anomaly alerts)..."
	@mkdir -p scratch_repo
	./target/release/nos-watcher

# ─── Demo Pipeline ────────────────────────────────────────────────────────────
#
# Full pipeline: anomaly detection -> alert -> nos-watcher -> ironclad-agent -> WASM sandbox
#
# Usage:  make demo
# Stop:   Ctrl+C  or  make demo-stop

demo: build
	@echo ""
	@echo "========================================"
	@echo "  Ironclad Agent - Full Demo Pipeline"
	@echo "========================================"
	@echo ""
	@echo "  eBPF/Anomaly Detection -> nos-watcher -> ironclad-agent -> WASM Sandbox"
	@echo ""
	@mkdir -p scratch_repo
	@echo "Starting nos-watcher in background..."
	@./target/release/nos-watcher > /tmp/nos-watcher.log 2>&1 & echo "$$!" > .nos-watcher.pid
	@sleep 1
	@echo "Starting anomaly detection in background..."
	@python3 -u monitor/detect.py > /tmp/detect.log 2>&1 & echo "$$!" > .detect.pid
	@echo ""
	@echo "Pipeline running! PIDs: watcher=$$(cat .nos-watcher.pid) detect=$$(cat .detect.pid)"
	@echo "  Logs: /tmp/nos-watcher.log  /tmp/detect.log"
	@echo "  Stop: Ctrl+C or 'make demo-stop'"
	@echo ""
	@echo "Following detect log (Ctrl+C to stop all)..."
	@trap 'make demo-stop' INT; \
	tail -f /tmp/detect.log /tmp/nos-watcher.log; \

demo-stop:
	@echo "Stopping pipeline..."
	@kill $$(cat .nos-watcher.pid 2>/dev/null) 2>/dev/null; \
	kill $$(cat .detect.pid 2>/dev/null) 2>/dev/null; \
	rm -f .nos-watcher.pid .detect.pid; \
	echo "Pipeline stopped."

# ─── Clean ────────────────────────────────────────────────────────────────────

clean:
	@echo "Cleaning build artifacts..."
	cargo clean
