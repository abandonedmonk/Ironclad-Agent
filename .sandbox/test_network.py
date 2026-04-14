import urllib

# Attempt to fetch from the web
try:
    import urllib.request

    urllib.request.urlopen("http://google.com", timeout=2)
    print("ERROR: Network access should be blocked!")
except Exception as e:
    print(f"Good: Network blocked with: {type(e).__name__}: {e}")
