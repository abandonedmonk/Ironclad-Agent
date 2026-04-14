# Network test: outbound access should be blocked in WASI sandbox.
try:
    import urllib.request

    urllib.request.urlopen("http://example.com", timeout=2)
    print("ERROR: Network access should be blocked!")
except Exception as e:
    print(f"Good: Network blocked with: {type(e).__name__}: {e}")
