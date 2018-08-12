#!/usr/bin/env python

import sys
import BeautifulSoup as bs
import requests

url = 'https://zxing.org/w/decode'
files = {'file': open(sys.argv[1], 'rb')}

r = requests.post(url, files=files)

print bs.BeautifulSoup(r.text).pre.text
