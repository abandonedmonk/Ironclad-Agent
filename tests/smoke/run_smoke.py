from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SmokeCase:
    name: str
    script: Path
    expected_exit: int | None
    must_contain: tuple[str, ...]


def run_case(case: SmokeCase, root: Path) -> tuple[bool, str]:
    cmd = ["cargo", "run", "--", str(case.script)]
    proc = subprocess.run(
        cmd,
        cwd=root,
        capture_output=True,
        text=True,
        timeout=120,
    )
    combined = f"{proc.stdout}\n{proc.stderr}"

    ok = True
    reasons: list[str] = []

    if case.expected_exit is not None and proc.returncode != case.expected_exit:
        ok = False
        reasons.append(f"exit={proc.returncode}, expected={case.expected_exit}")

    for token in case.must_contain:
        if token not in combined:
            ok = False
            reasons.append(f"missing token: {token!r}")

    summary = "PASS" if ok else "FAIL"
    detail = "" if ok else " | " + "; ".join(reasons)
    return ok, f"[{summary}] {case.name}{detail}"


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    scripts = root / "tests" / "smoke" / "scripts"

    cases = [
        SmokeCase(
            name="normal script",
            script=scripts / "test_normal.py",
            expected_exit=0,
            must_contain=("normal_ok",),
        ),
        SmokeCase(
            name="network blocked",
            script=scripts / "test_network.py",
            expected_exit=0,
            must_contain=("Good: Network blocked",),
        ),
        SmokeCase(
            name="filesystem isolated",
            script=scripts / "test_filesystem_escape.py",
            expected_exit=0,
            must_contain=(
                "Good: Filesystem isolated",
                "Good: Sandbox readable",
            ),
        ),
        SmokeCase(
            name="fuel exhausted",
            script=scripts / "test_infinite.py",
            expected_exit=1,
            must_contain=("fuel exhausted",),
        ),
    ]

    print("Running smoke suite...")
    passed = 0

    for case in cases:
        ok, line = run_case(case, root)
        print(line)
        if ok:
            passed += 1

    total = len(cases)
    print(f"\nResult: {passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
