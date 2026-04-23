from __future__ import annotations

import argparse
import shutil
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RunnerResult:
    label: str
    timings_ms: list[float]


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    if p <= 0:
        return min(values)
    if p >= 100:
        return max(values)

    sorted_values = sorted(values)
    rank = (p / 100.0) * (len(sorted_values) - 1)
    low = int(rank)
    high = min(low + 1, len(sorted_values) - 1)
    frac = rank - low
    return sorted_values[low] * (1 - frac) + sorted_values[high] * frac


def summarize(values: list[float]) -> dict[str, float]:
    return {
        "median": statistics.median(values),
        "p95": percentile(values, 95),
        "p99": percentile(values, 99),
        "min": min(values),
        "max": max(values),
    }


def to_docker_mount(path: Path) -> str:
    # Docker on Windows is happier with forward slashes in bind mounts.
    return path.resolve().as_posix()


def run_once(
    cmd: list[str], cwd: Path, timeout_sec: int
) -> tuple[float, subprocess.CompletedProcess[str]]:
    start = time.perf_counter()
    completed = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout_sec,
    )
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return elapsed_ms, completed


def ensure_docker_image(image: str, cwd: Path, timeout_sec: int) -> None:
    inspect = subprocess.run(
        ["docker", "image", "inspect", image],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout_sec,
    )
    if inspect.returncode == 0:
        return

    print(f"[docker] pulling missing image: {image}")
    subprocess.run(
        ["docker", "pull", image],
        cwd=cwd,
        check=True,
        text=True,
        timeout=timeout_sec,
    )


def ensure_runtime_binary(root: Path) -> Path:
    exe_name = (
        "ironclad-runtime.exe" if sys.platform.startswith("win") else "ironclad-runtime"
    )
    runtime_path = root / "target" / "release" / exe_name

    if runtime_path.exists():
        return runtime_path

    print("[build] release runtime not found; building it now...")
    subprocess.run(
        ["cargo", "build", "--release", "-p", "ironclad-runtime"],
        cwd=root,
        check=True,
        text=True,
    )

    if not runtime_path.exists():
        raise FileNotFoundError(f"release runtime missing at {runtime_path}")

    return runtime_path


def benchmark_ironclad(
    root: Path, script: Path, iterations: int, warmup: int, timeout_sec: int
) -> RunnerResult:
    runtime = ensure_runtime_binary(root)
    timings: list[float] = []

    total_runs = warmup + iterations
    for i in range(total_runs):
        cmd = [str(runtime), str(script)]
        elapsed, completed = run_once(cmd, cwd=root, timeout_sec=timeout_sec)
        if completed.returncode != 0:
            raise RuntimeError(
                f"ironclad failed on iter {i + 1}: exit={completed.returncode}\n"
                f"stdout:\n{completed.stdout}\n"
                f"stderr:\n{completed.stderr}"
            )
        if i < warmup:
            continue
        timings.append(elapsed)

    return RunnerResult("ironclad-runtime", timings)


def benchmark_docker(
    root: Path, script: Path, iterations: int, warmup: int, timeout_sec: int
) -> RunnerResult:
    if shutil.which("docker") is None:
        raise EnvironmentError("docker is not installed or not in PATH")

    image = "python:3.12-alpine"
    ensure_docker_image(image, root, timeout_sec)

    workdir = script.parent
    mount = to_docker_mount(workdir)
    script_name = script.name
    timings: list[float] = []

    total_runs = warmup + iterations
    for i in range(total_runs):
        cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{mount}:/work",
            "-w",
            "/work",
            image,
            "python",
            script_name,
        ]
        elapsed, completed = run_once(cmd, cwd=root, timeout_sec=timeout_sec)
        if completed.returncode != 0:
            raise RuntimeError(
                f"docker run failed on iter {i + 1}: exit={completed.returncode}\n"
                f"stdout:\n{completed.stdout}\n"
                f"stderr:\n{completed.stderr}"
            )
        if i < warmup:
            continue
        timings.append(elapsed)

    return RunnerResult("docker python:3.12-alpine", timings)


def print_table(results: list[RunnerResult]) -> None:
    headers = ("Runner", "Median (ms)", "P95 (ms)", "P99 (ms)", "Min (ms)", "Max (ms)")
    rows: list[tuple[str, str, str, str, str, str]] = []

    for result in results:
        s = summarize(result.timings_ms)
        rows.append(
            (
                result.label,
                f"{s['median']:.2f}",
                f"{s['p95']:.2f}",
                f"{s['p99']:.2f}",
                f"{s['min']:.2f}",
                f"{s['max']:.2f}",
            )
        )

    col_widths = [len(h) for h in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            col_widths[idx] = max(col_widths[idx], len(cell))

    def fmt_row(items: tuple[str, str, str, str, str, str]) -> str:
        return " | ".join(item.ljust(col_widths[idx]) for idx, item in enumerate(items))

    print(fmt_row(headers))
    print("-+-".join("-" * w for w in col_widths))
    for row in rows:
        print(fmt_row(row))

    if len(results) == 2:
        a = summarize(results[0].timings_ms)["median"]
        b = summarize(results[1].timings_ms)["median"]
        if a > 0:
            print(f"\nSpeedup vs Docker (median): {b / a:.2f}x")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark Ironclad runtime vs Docker Python"
    )
    parser.add_argument(
        "--iterations", type=int, default=100, help="Number of runs per runner"
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=5,
        help="Warmup runs per runner (not included in stats)",
    )
    parser.add_argument(
        "--script",
        type=Path,
        default=Path(__file__).resolve().parent / "scripts" / "benchmark_workload.py",
        help="Python workload script",
    )
    parser.add_argument(
        "--timeout", type=int, default=60, help="Timeout per run in seconds"
    )
    parser.add_argument(
        "--skip-docker", action="store_true", help="Benchmark only Ironclad"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.iterations <= 0:
        print("iterations must be > 0", file=sys.stderr)
        return 2
    if args.warmup < 0:
        print("warmup must be >= 0", file=sys.stderr)
        return 2

    root = Path(__file__).resolve().parents[2]
    script = args.script.resolve()

    if not script.exists():
        print(f"workload script not found: {script}", file=sys.stderr)
        return 2

    print(
        f"Running benchmark with {args.iterations} measured iteration(s) "
        f"(+{args.warmup} warmup)..."
    )
    print(f"Workload: {script}")

    results: list[RunnerResult] = []

    try:
        results.append(
            benchmark_ironclad(root, script, args.iterations, args.warmup, args.timeout)
        )
    except Exception as exc:
        print(f"[error] ironclad benchmark failed: {exc}", file=sys.stderr)
        return 1

    if not args.skip_docker:
        try:
            results.append(
                benchmark_docker(
                    root, script, args.iterations, args.warmup, args.timeout
                )
            )
        except Exception as exc:
            print(f"[warn] docker benchmark skipped: {exc}")

    print()
    print_table(results)

    if len(results) == 1 and not args.skip_docker:
        print("\nDocker result unavailable. Install/start Docker Desktop and rerun.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
