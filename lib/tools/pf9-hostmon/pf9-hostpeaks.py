#!/usr/bin/python

# To-Do's:
# 1. Add Column: Project-Name
# 2. Add Memory_Util
# 3. Sort by CPU_UTIL

import sys
import os.path
import json
import signal
import dateutil.parser as dp

def usage():
    print "usage: {} <yyyy-mm-dd> <du>".format(sys.argv[0])
    sys.exit(1)

def lassert(m):
    if m != None:
        print "ASSERT: {}".format(m)
    sys.exit(1)

def sigint_handler(signum, frame):
    None

def get_instance_info(instance_id):
    json_results_file = "/tmp/pf9-hostmon-server.{}.tmp.json".format(os.getppid())
    os.system("openstack server show -f json {} > {}".format(instance_id,json_results_file))

    # validate json_results_file
    if os.path.isfile(json_results_file):
        try:
            json_data=open(json_results_file)
            server_data = json.load(json_data)
            json_data.close()
        except:
            return None
        else:
            return server_data

def get_cpu_metrics(instance_id):
    json_results_file = "/tmp/pf9-hostmon-gnocchi.{}.tmp.json".format(os.getppid())
    os.system("gnocchi measures show -f json --resource-id {} cpu_util 2>/dev/null > {}".format(instance_id,json_results_file))

    # validate json_results_file
    if os.path.isfile(json_results_file):
        try:
            json_data=open(json_results_file)
            data = json.load(json_data)
            json_data.close()
        except:
            return None
        else:
            return data

def get_peak_cpu(json_data,target_date):
    max_cpu = max_ts = 0
    for sample_data in json_data:
        try:
            sample_data['value']
        except:
            continue
        else:
            if sample_data['timestamp'].split('T')[0] == target_date and sample_data['value'] > max_cpu:
                max_cpu = round(sample_data['value'],2)
                max_ts = sample_data['timestamp']
                return max_cpu, max_ts
    return -1, -1

def get_flavor_metadata(instance_flavor):
    # lookup flavor metadata
    instance_flavor_name = instance_flavor.split(' ')[0]
    json_results_file = "/tmp/pf9-hostmon-flavor.{}.tmp.json".format(os.getppid())
    os.system("openstack flavor show -f json {} > {}".format(instance_flavor_name,json_results_file))

    # validate json_results_file
    instance_ram = instance_cpu = ""
    if os.path.isfile(json_results_file):
        # get flavor
        try:
            json_data=open(json_results_file)
            server_data = json.load(json_data)
            json_data.close()
        except:
            return instance_ram, instance_cpu
        else:
            instance_ram = server_data['ram']
            instance_cpu = server_data['vcpus']

    return instance_ram, instance_cpu

def get_project_name(project_id):
    # lookup project name
    json_results_file = "/tmp/pf9-hostmon-project.{}.tmp.json".format(os.getppid())
    os.system("openstack project show -f json {} > {}".format(project_id,json_results_file))

    # validate json_results_file
    if os.path.isfile(json_results_file):
        # get flavor
        try:
            json_data=open(json_results_file)
            server_data = json.load(json_data)
            json_data.close()
        except:
            return ""
        else:
            return server_data['name']

def write_instance_metrics_to_db(last_timestamp,instance_id,instance_name,instance_flavor,project_id,instance_db):
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
                        instance_db.write("{},{},{},{},{}\r\n".format(metric_data['timestamp'],instance_name,instance_flavor,metric_data['value'],project_id))

# print usage
if len(sys.argv) < 3:
    usage()

# get target date
target_date = sys.argv[1]
du_name = sys.argv[2]

# initialize limit
limit = 0
if len(sys.argv) == 4:
    limit = int(sys.argv[3])

# get list of server IDs
json_results_file = "/tmp/pf9-hostmon-servers.{}.tmp.json".format(os.getppid())
os.system("openstack server list --all-projects -f json > {}".format(json_results_file))

# validate json_results_file
if not os.path.isfile(json_results_file):
    lassert("failed to open <json_results_file>: {}".format(json_results_file))

# print csv header
print "INSTANCE-NAME,MAX-CPU-%,CPU,RAM,FLAVOR,MAX-CPU-TIMESTAMP,PROJECT"

# process server IDs (get ceilometer stats and process)
try:
    json_data=open(json_results_file)
    data = json.load(json_data)
    json_data.close()
except:
    lassert("failed to process <json_results_file>")
else:
    cnt = 0
    for instance_data in data:
        try:
            instance_data['Name']
        except:
            continue
        else:
            # get instance metrics
            instance_metrics_cpu = get_cpu_metrics(instance_data['ID'])

            if instance_metrics_cpu == None:
               continue

            # create metrics directory for du
            metrics_dir = "instance_data/{}/{}".format(du_name,target_date)
            try:
                os.stat("instance_data/{}".format(du_name))
            except:
                os.mkdir("instance_data/{}".format(du_name))  

            # create metrics directory for du
            try:
                os.stat("instance_data/{}/{}".format(du_name,target_date))
            except:
                os.mkdir("instance_data/{}/{}".format(du_name,target_date))  

            # update host metrics
            metrics_db_file = "instance_data/{}".format(instance_data['Name'])
            if not os.path.isfile(metrics_db_file):
                instance_db_fh = open(metrics_db_file, "w+")
            else:
                instance_db_fh = open(metrics_db_file, "a+")

            # update host peaks
            if (limit == 0) or (cnt < limit):
                instance_metadata = get_instance_info(instance_data['ID'])
                project_name = get_project_name(instance_metadata['project_id'])
                instance_ram, instance_cpu = get_flavor_metadata(instance_metadata['flavor'])
                max_cpu, max_ts = get_peak_cpu(instance_metrics_cpu,target_date)
                if max_cpu != -1:
                    print "{},{},{},{},{},{},{}".format(instance_data['Name'],max_cpu,instance_cpu,instance_ram,instance_data['Flavor'],project_name,max_ts)
                cnt += 1
            else:
                break
# exit
sys.exit(0)
