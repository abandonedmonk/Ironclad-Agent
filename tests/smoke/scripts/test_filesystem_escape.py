# Filesystem test: host paths should be blocked, sandbox path should be readable.
try:
    with open("/etc/passwd", "r", encoding="utf-8") as f:
        print("ERROR: Host filesystem accessible!")
except (FileNotFoundError, PermissionError, OSError) as e:
    print(f"Good: Filesystem isolated with: {type(e).__name__}")

# Runtime always stages the source script into /sandbox/script.py.
try:
    with open("/sandbox/script.py", "r", encoding="utf-8") as f:
        lines = len(f.readlines())
        print(f"Good: Sandbox readable (staged script has {lines} lines)")
except Exception as e:
    print(f"ERROR: Sandbox not accessible: {e}")
