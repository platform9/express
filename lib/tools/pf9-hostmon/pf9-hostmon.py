#!/usr/bin/python

import sys
import os.path
import json
import signal
#from datetime import datetime
#import calendar
import dateutil.parser as dp

def usage():
    print "usage: {} [<hostname_filter>]".format(sys.argv[0]) 
    sys.exit(1)

def lassert(m):
    if m != None:
        print "ASSERT: {}".format(m)
    sys.exit(1)

def sigint_handler(signum, frame):
    None

def write_instance_metrics_to_db(last_timestamp,instance_id,instance_name,instance_flavor,instance_db):
    json_results_file = "/tmp/pf9-hostmon-gnocchi.tmp.json"
    os.system("gnocchi measures show -f json --resource-id {} cpu_util > {}".format(instance_id,json_results_file))

    # validate json_results_file
    if not os.path.isfile(json_results_file):
        lassert("failed to open <json_results_file>: {}".format(json_results_file))

    # process ceilometer metric: cpu_util
    try:
        json_data=open(json_results_file)
        metrics = json.load(json_data)
        json_data.close()
    except:
        lassert("failed to process <json_results_file>")
    else:
        for metric_data in metrics:
            try:
                metric_data['value']
            except:
                continue
            else:
                if last_timestamp == 0:
                    instance_db.write("{},{},{},{}\r\n".format(metric_data['timestamp'],instance_name,instance_flavor,metric_data['value']))
                else:
                    last_ts = dp.parse(last_timestamp)
                    last_epoch = last_ts.strftime('%s')
                    current_ts = dp.parse(metric_data['timestamp'])
                    current_epoch = current_ts.strftime('%s')
                    if current_epoch > last_epoch:
                        instance_db.write("{},{},{},{}\r\n".format(metric_data['timestamp'],instance_name,instance_flavor,metric_data['value']))

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
    instances = json.load(json_data)
    json_data.close()
except:
    lassert("failed to process <json_results_file>")
else:
    for instance_data in instances:
        try:
            instance_data['Name']
        except:
            continue
        else:
            instance_db_file = "instance_data/{}".format(instance_data['Name'])
            if not os.path.isfile(instance_db_file):
                instance_db_fh = open(instance_db_file, "w+")
            else:
                instance_db_fh = open(instance_db_file, "a+")

            metric_lines = instance_db_fh.readlines()
            if len(metric_lines) > 0:
                last_timestamp = metric_lines[len(metric_lines)-1].split(',')[0]
            else:
                last_timestamp = 0
            write_instance_metrics_to_db(last_timestamp,instance_data['ID'],instance_data['Name'],instance_data['Flavor'],instance_db_fh)

# exit
sys.exit(0)

