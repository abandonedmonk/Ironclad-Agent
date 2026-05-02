from dateutil.parser import parse

# REQUIRES: python-dateutil, six

print(parse("2022-01-01").strftime("%Y-%m-%d"))
