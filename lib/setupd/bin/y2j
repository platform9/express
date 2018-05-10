import yaml
import json
import sys

fname = sys.argv[1]
with open(fname, 'r') as f:
    data = yaml.load(f)
    out = json.dumps(data, separators=(',', ':'))
    print out
