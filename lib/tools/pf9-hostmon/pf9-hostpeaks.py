#!/usr/bin/python

import sys
import os.path
import json
import signal

def usage():
    print "usage: {} <yyyy-mm-dd>".format(sys.argv[0])
    sys.exit(1)

def lassert(m):
    if m != None:
        print "ASSERT: {}".format(m)
    sys.exit(1)

def sigint_handler(signum, frame):
    None

def get_peak_cpu(instance_id, target_data):
    json_results_file = "/tmp/pf9-hostmon-gnocchi.tmp.json"
    os.system("gnocchi measures show -f json --resource-id {} cpu_util > {}".format(instance_id,json_results_file))

    # validate json_results_file
    if os.path.isfile(json_results_file):
        # process ceilometer metric: cpu_util
        try:
            json_data=open(json_results_file)
            data = json.load(json_data)
            json_data.close()
        except:
            return -1, -1
        else:
            max_cpu = max_ts = 0
            for sample_data in data:
                try:
                    sample_data['value']
                except:
                    continue
                else:
                    if sample_data['timestamp'].split('T')[0] == target_data and sample_data['value'] > max_cpu:
                        max_cpu = sample_data['value']
                        max_ts = sample_data['timestamp']
                        return max_cpu, max_ts
    return -1, -1

def get_project_id(instance_id):
    json_results_file = "/tmp/pf9-hostmon-server.tmp.json"
    os.system("openstack server show -f json -c project_id {} > {}".format(instance_id,json_results_file))

    # validate json_results_file
    project_id = ""
    if os.path.isfile(json_results_file):
        # get project id
        try:
            json_data=open(json_results_file)
            server_data = json.load(json_data)
            json_data.close()
        except:
            return project_id
        else:
            project_id = server_data['project_id']
    return project_id

# print usage
if len(sys.argv) != 2:
    usage()

# get target date
target_date = sys.argv[1]

# get list of server IDs
json_results_file = "/tmp/pf9-hostmon-servers.tmp.json"
os.system("openstack server list --all-projects -f json > {}".format(json_results_file))

# validate json_results_file
if not os.path.isfile(json_results_file):
    lassert("failed to open <json_results_file>: {}".format(json_results_file))

# print csv header
print "INSTANCE-NAME,FLAVOR,MAX-CPU,MAX-CPU-TIMESTAMP,PROJECT-ID"

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
            project_id = get_project_id(sample_data['ID'])
            max_cpu, max_ts = get_peak_cpu(sample_data['ID'],target_date)
            if max_cpu != -1:
                print "{},{},{},{},{}".format(sample_data['Name'],sample_data['Flavor'],max_cpu,max_ts,project_id)

# exit
sys.exit(0)
