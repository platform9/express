#!/usr/bin/python

import sys
import os.path
import json
import signal

def usage():
    print "usage: {} [<hostname_filter>]".format(sys.argv[0]) 
    sys.exit(1)

def lassert(m):
    if m != None:
        print "ASSERT: {}".format(m)
    sys.exit(1)

def sigint_handler(signum, frame):
    None

def get_peak_cpu(instance_id):
    json_results_file = "/tmp/pf9-hostmon-gnocchi.tmp.json"
    os.system("gnocchi measures show -f json --resource-id {} cpu_util > {}".format(instance_id,json_results_file))

    # validate json_results_file
    if not os.path.isfile(json_results_file):
        lassert("failed to open <json_results_file>: {}".format(json_results_file))

    # process ceilometer metric: cpu_util
    try:
        json_data=open(json_results_file)
        data = json.load(json_data)
        json_data.close()
    except:
        lassert("failed to process <json_results_file>")
    else:
        max_cpu = max_ts = 0
        for sample_data in data:
            try:
                sample_data['value']
            except:
                continue
            else:
                if sample_data['value'] > max_cpu:
                    max_cpu = sample_data['value']
                    max_ts = sample_data['timestamp']
    return max_cpu, max_ts

# print usage
if len(sys.argv) == 2 and sys.argv[1] == "-h":
    usage

# assign commandine parameters
if len(sys.argv) == 2:
  hostname_filter = sys.argv[1]

# get list of server IDs
json_results_file = "/tmp/pf9-hostmon-servers.tmp.json"
os.system("openstack server list -f json > {}".format(json_results_file))

# validate json_results_file
if not os.path.isfile(json_results_file):
    lassert("failed to open <json_results_file>: {}".format(json_results_file))

# process server IDs (get ceilometer stats and process)
try:
    json_data=open(json_results_file)
    data = json.load(json_data)
    json_data.close()
except:
    lassert("failed to process <json_results_file>")
else:
    for sample_data in data:
        try:
            sample_data['Name']
        except:
            continue
        else:
            max_cpu, max_ts = get_peak_cpu(sample_data['ID'])
            print "{},{},{},{}".format(sample_data['Name'],sample_data['Flavor'],max_cpu,max_ts)

# exit
sys.exit(0)

