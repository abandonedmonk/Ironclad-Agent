# REQUIRES: python-dateutil, six

import dateutil.parser
import six

date_string = '2022-01-01'
parsed_date = dateutil.parser.parse(date_string)

print(parsed_date)