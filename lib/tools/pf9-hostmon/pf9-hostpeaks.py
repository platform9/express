#!/usr/bin/python

import sys
import os.path
import json
import signal
import dateutil.parser as dp
import plotly.graph_objs as go
import plotly
import plotly.plotly as py

# global vars
metrics_timeseries_base = "du_metrics"
metrics_peak_pase = "du_peakdata"

def usage():
    print "Usage: {} <yyyy-mm-dd> <du> [<limit>]".format(sys.argv[0])
    sys.exit(1)

def lassert(m):
    if m != None:
        print "ASSERT: {}".format(m)
    sys.exit(1)

def sigint_handler(signum, frame):
    None

def get_instance_info(instance_id):
    json_results_file = "/tmp/pf9-hostmon-server.{}.tmp.json".format(os.getppid())
    os.system("openstack server show -f json {} 2>/dev/null > {}".format(instance_id,json_results_file))

    # validate json_results_file
    if os.path.isfile(json_results_file):
        try:
            json_data=open(json_results_file)
            os.remove(json_results_file)
            server_data = json.load(json_data)
            json_data.close()
        except:
            return None
        else:
            return server_data

def get_cpu_metrics(instance_id,target_date):
    # configure search filter
    start_date = "{}T00:00:00+00:00".format(target_date)
    end_date = "{}T23:59:59+00:00".format(target_date)

    json_results_file = "/tmp/pf9-hostmon-gnocchi.{}.tmp.json".format(os.getppid())
    os.system("gnocchi measures show -f json --start {} --stop {} --resource-id {} cpu_util 2>/dev/null > {}".format(start_date,end_date,instance_id,json_results_file))

    # validate json_results_file
    if os.path.isfile(json_results_file):
        try:
            json_data=open(json_results_file)
            os.remove(json_results_file)
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

def populate_plot_data(json_data):
    data_x = []
    data_y = []
    for sample_data in json_data:
        try:
            sample_data['value']
        except:
            continue
        else:
            data_x.append(sample_data['timestamp'])
            data_y.append(round(sample_data['value'],2))

    return data_x, data_y

def get_flavor_metadata(instance_flavor):
    # lookup flavor metadata
    instance_flavor_name = instance_flavor.split(' ')[0]
    json_results_file = "/tmp/pf9-hostmon-flavor.{}.tmp.json".format(os.getppid())
    os.system("openstack flavor show -f json {} 2>/dev/null > {}".format(instance_flavor_name,json_results_file))

    # validate json_results_file
    instance_ram = instance_cpu = ""
    if os.path.isfile(json_results_file):
        # get flavor
        try:
            json_data=open(json_results_file)
            os.remove(json_results_file)
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
    os.system("openstack project show -f json {} 2>/dev/null > {}".format(project_id,json_results_file))

    # validate json_results_file
    if os.path.isfile(json_results_file):
        # get flavor
        try:
            json_data=open(json_results_file)
            os.remove(json_results_file)
            server_data = json.load(json_data)
            json_data.close()
        except:
            return ""
        else:
            return server_data['name']

def write_instance_metrics_to_db(metrics_db,json_data,last_timestamp,instance_id,instance_name,instance_flavor,project_id,instance_db):
    for metric_data in json_data:
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
                    metrics_db.write("{},{},{},{},{}\r\n".format(metric_data['timestamp'],instance_name,instance_flavor,metric_data['value'],project_id))

def init_metrics_db(du_name,target_date,instance_name):
    # create directory for du
    metrics_dir = "{}/{}/{}".format(metrics_timeseries_base,du_name,target_date)
    try:
        os.stat("{}/{}".format(metrics_timeseries_base,du_name))
    except:
        os.mkdir("{}/{}".format(metrics_timeseries_base,du_name))  

    # create directory for du/date
    try:
        os.stat("{}/{}/{}".format(metrics_timeseries_base,du_name,target_date))
    except:
        os.mkdir("{}/{}/{}".format(metrics_timeseries_base,du_name,target_date))  

    # create file for du/date/instance
    metrics_db_file = "{}/{}".format(metrics_dir,instance_data['Name'])
    if not os.path.isfile(metrics_db_file):
        instance_db_fh = open(metrics_db_file, "w+")
    else:
        instance_db_fh = open(metrics_db_file, "a+")

    return metrics_dir, instance_db_fh

def init_peak_db(du_name,target_date):
    # create directory for du
    try:
        os.stat("{}/{}".format(metrics_peak_pase,du_name))
    except:
        os.mkdir("{}/{}".format(metrics_peak_pase,du_name))  

    # create directory for du/date
    try:
        os.stat("{}/{}/{}".format(metrics_peak_pase,du_name,target_date))
    except:
        os.mkdir("{}/{}/{}".format(metrics_peak_pase,du_name,target_date))  

    # create file for du/date/peaks
    peak_db_file = "{}/{}/{}/instance-metrics.{}.{}.csv".format(metrics_peak_pase,du_name,target_date,du_name,target_date)
    if os.path.isfile(peak_db_file):
      os.remove(peak_db_file)
    peak_db_fh = open(peak_db_file, "w+")

    return peak_db_fh

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
os.system("openstack server list --all-projects -f json 2>/dev/null > {}".format(json_results_file))

# validate json_results_file
if not os.path.isfile(json_results_file):
    lassert("failed to open <json_results_file>: {}".format(json_results_file))

# process server IDs (get ceilometer stats and process)
try:
    json_data=open(json_results_file)
    os.remove(json_results_file)
    data = json.load(json_data)
    json_data.close()
except:
    lassert("failed to process <json_results_file>")
else:
    cnt = 0
    plot_data= []

    # initialize peak database
    peak_db_fh = init_peak_db(du_name,target_date)

    for instance_data in data:
        try:
            instance_data['Name']
        except:
            continue
        else:
            # initialize instance-specific timeseries database
            metrics_dir, instance_db_fh = init_metrics_db(du_name,target_date,instance_data['Name'])

            # get instance metrics
            instance_metrics_cpu = get_cpu_metrics(instance_data['ID'],target_date)
            if instance_metrics_cpu == None:
               continue

            # lookup instance metadata
            instance_metadata = get_instance_info(instance_data['ID'])

            # initialize instance-plot data
            instance_plot_data_x, instance_plot_data_y = populate_plot_data(instance_metrics_cpu)
            trace_instance = go.Scatter(
                x = instance_plot_data_x,
                y = instance_plot_data_y,
                name = instance_metadata['name'],
            )
            plot_data.append(trace_instance)

            # write metrics to timeseries database
            metric_lines = instance_db_fh.readlines()
            if len(metric_lines) > 0:
                last_timestamp = metric_lines[len(metric_lines)-1].split(',')[0]
            else:
                last_timestamp = 0
            write_instance_metrics_to_db(instance_db_fh,instance_metrics_cpu,last_timestamp,instance_data['ID'],instance_data['Name'],instance_data['Flavor'],instance_metadata['project_id'],instance_db_fh)

            # update metric databases
            if cnt == 0:
                peak_db_fh.write("INSTANCE-NAME,MAX-CPU-%,CPU,RAM,FLAVOR,PROJECT,TIMESTAMP-MAX_CPU\n")

            project_name = get_project_name(instance_metadata['project_id'])
            instance_ram, instance_cpu = get_flavor_metadata(instance_metadata['flavor'])
            max_cpu, max_ts = get_peak_cpu(instance_metrics_cpu,target_date)
            if max_cpu != -1:
                peak_db_fh.write("{},{},{},{},{},{},{}\n".format(instance_data['Name'],max_cpu,instance_cpu,instance_ram,instance_data['Flavor'],project_name,max_ts))

            # implement limit
            cnt += 1
            if (limit != 0) and (cnt >= limit):
                break

    # configure graph
    graph_storage = "online"
    layout = dict(
        title = "{} : Instance Utilization Trend".format(du_name),
        xaxis = dict(title = 'Date'),
        yaxis = dict(title = 'CPU Utilization (%)'),
    )
    fig = dict(data=plot_data, layout=layout)

    # build graph (online mode)
    if graph_storage == "online":
        plotly.tools.set_credentials_file(username='dwrightco1', api_key='D0CdsmAnWdkeS4nWrNFw')
        graph_url = py.plot(fig)
        link_db = "{}/{}/{}/link_to_graph_cpu.dat".format(metrics_timeseries_base,du_name,target_date)
        if os.path.isfile(link_db):
            os.remove(link_db)
        link_db_fh = open(link_db, "w+")
        link_db_fh.write(graph_url)

    # build graph (offline mode)
    if graph_storage == "offline":
        plotly.offline.plot(fig, filename = "{}/graph-cpu.html".format(metrics_dir))

# exit
sys.exit(0)
