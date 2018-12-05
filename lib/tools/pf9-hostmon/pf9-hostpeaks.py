#!/usr/bin/python

import sys
import os.path
import argparse
import csv
import json
import signal
import dateutil.parser as dp
from pygooglechart import SimpleLineChart
from pygooglechart import Axis

# global vars
metrics_timeseries_base = "du_metrics"
metrics_peak_pase = "du_peakdata"
graph_storage = "online"
instance_map = {}

def _parse_args():
    ap = argparse.ArgumentParser(sys.argv[0],formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument('target_date', help='target date for metrics analysis, format = YYYY-MM-DD')
    ap.add_argument('du_name', help='name of the DU (just a string for reporting purposes)')
    ap.add_argument('-l', required=False, type=int, dest='limit', default=0, help='limit the number of systems processed')
    ap.add_argument('-g', default=False, action='store_true', dest='flag_graph_only',
                    help='skip metrics collection and build graphs from previously-collected metrics')
    return ap.parse_args()

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

def read_metrics_file(instance_id,du_name,target_date,metrics_dir):
    # initialize json return data
    json_data = []

    # open CSV-based metrics db file
    csv_db_file = "{}/{}".format(metrics_dir,instance_map[instance_id])
    if os.path.isfile(csv_db_file):
        try:
            csvfile = open(csv_db_file, 'r')
        except:
            print "failed to open: {}".format(csv_db_file)
            return None
        else:
            fieldnames = ("timestamp","hostname","flavor","value")
            reader = csv.DictReader( csvfile.readlines(), fieldnames)
            for row in reader:
                json_row = {'timestamp': row['timestamp'], 'value': float(row['value'])}
                json_data.append(json_row)
            return json_data

def get_cpu_metrics(instance_id,du_name,target_date,flag_graph_only,metrics_dir):
    # configure search filter
    start_date = "{}T00:00:00+00:00".format(target_date)
    end_date = "{}T23:59:59+00:00".format(target_date)

    # get instance metrics (from OpenStack or local file, based on flag_graph_only flag)
    if not flag_graph_only:
        json_results_file = "/tmp/pf9-hostmon-gnocchi-cpu.{}.tmp.json".format(os.getppid())
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
        data = read_metrics_file(instance_id,du_name,target_date,metrics_dir)
    
    return data

def get_mem_metrics(instance_id,du_name,target_date,flag_graph_only,metrics_dir):
    # configure search filter
    start_date = "{}T00:00:00+00:00".format(target_date)
    end_date = "{}T23:59:59+00:00".format(target_date)

    # get instance metrics (from OpenStack or local file, based on flag_graph_only flag)
    if not flag_graph_only:
        json_results_file = "/tmp/pf9-hostmon-gnocchi-mem.{}.tmp.json".format(os.getppid())
        os.system("gnocchi measures show -f json --start {} --stop {} --resource-id {} memory.usage 2>/dev/null > {}".format(start_date,end_date,instance_id,json_results_file))
    
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
        data = read_metrics_file(instance_id,du_name,target_date,metrics_dir)
    
    return data

def get_peak_cpu(json_data_cpu,json_data_mem,instance_ram,target_date):
    max_cpu = max_cpu_ts = max_mem = max_mem_ts = -1
    for metric_cpu in json_data_cpu:
        try:
            metric_cpu['value']
        except:
            continue
        else:
            if metric_cpu['timestamp'].split('T')[0] == target_date and metric_cpu['value'] > max_cpu:
                max_cpu = round(metric_cpu['value'],2)
                max_cpu_ts = metric_cpu['timestamp']

    for metric_mem in json_data_mem:
        try:
            metric_mem['value']
        except:
            continue
        else:
            if metric_mem['timestamp'].split('T')[0] == target_date and metric_mem['value'] > max_mem:
                max_mem = round((metric_mem['value']/instance_ram)*100,2)
                max_mem_ts = metric_mem['timestamp']

    return max_cpu, max_cpu_ts, max_mem, max_mem_ts

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

################################################################################
## main()
################################################################################
# parse arguments
args = _parse_args()

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
    peak_db_fh = init_peak_db(args.du_name,args.target_date)

    # process each instance
    for instance_data in data:
        try:
            instance_data['Name']
        except:
            continue
        else:
            # implement limit
            cnt += 1
            if (args.limit != 0) and (cnt > args.limit):
                break

            # initialize instance-specific timeseries database
            metrics_dir, instance_db_fh = init_metrics_db(args.du_name,args.target_date,instance_data['Name'])

            # lookup instance metadata
            instance_metadata = get_instance_info(instance_data['ID'])
            instance_map[instance_data['ID']] = instance_metadata['name']

            # get instance metrics
            instance_metrics_cpu = get_cpu_metrics(instance_data['ID'],args.du_name,args.target_date,args.flag_graph_only,metrics_dir)
            if instance_metrics_cpu == None:
               continue

            # get memory metrics
            instance_metrics_mem = get_mem_metrics(instance_data['ID'],args.du_name,args.target_date,args.flag_graph_only,metrics_dir)
            if instance_metrics_mem == None:
               continue

            # initialize instance-plot data
            if graph_storage != "disabled":
                instance_plot_data_x, instance_plot_data_y = populate_plot_data(instance_metrics_cpu)
                trace_instance = {'xdata': instance_plot_data_x, 'ydata':instance_plot_data_y, 'instanceName':instance_metadata['name']}
                plot_data.append(trace_instance)

            # write metrics to timeseries database
            metric_lines = instance_db_fh.readlines()
            if len(metric_lines) > 0:
                last_timestamp = metric_lines[len(metric_lines)-1].split(',')[0]
            else:
                last_timestamp = 0
    
            write_instance_metrics_to_db(instance_db_fh,instance_metrics_cpu,last_timestamp,
                instance_data['ID'],instance_data['Name'],instance_data['Flavor'],
                instance_metadata['project_id'],instance_db_fh)

            # update metric databases
            if cnt == 1:
                peak_db_fh.write("INSTANCE-NAME,CPU,MAX-CPU-%,RAM-MB,MAX-MEMORY-%,FLAVOR,PROJECT,TIMESTAMP-MAX-CPU,TIMESTAMP-MAX-MEMORY\n")
    
            project_name = get_project_name(instance_metadata['project_id'])
            instance_ram, instance_cpu = get_flavor_metadata(instance_metadata['flavor'])
            max_cpu, max_cpu_ts, max_mem, max_mem_ts = get_peak_cpu(instance_metrics_cpu,instance_metrics_mem,instance_ram,args.target_date)
            if max_cpu != -1:
                peak_db_fh.write("{},{},{},{},{},{},{},{},{}\n".format(instance_data['Name'],instance_cpu,max_cpu,instance_ram,max_mem,instance_data['Flavor'],project_name,max_cpu_ts,max_mem_ts))

    # build graph
    if len(plot_data) == 0:
        print "INFO: no data collected - nothing to plot"
    else:
        # build graph
        chart = SimpleLineChart(900,600)
        chart.set_colours(['333333', '000000', '666666', '999999'])
        #chart.set_axis_style(0, '202020', font_size=10, alignment=0)
        #chart.set_axis_positions(index, [50])

        #near_far_axis_index = chart.set_axis_labels(Axis.BOTTOM, ['TIME'])
        #near_far_axis_index = chart.set_axis_labels(Axis.LEFT, ['CPU Utilization (%)'])
        trace_names = []
        for instance_metric in plot_data:
            trace_names.append(instance_metric['instanceName'])
            chart.add_data(instance_metric['ydata'])
        chart.set_legend(trace_names)
        chart.download('chart.png')

# exit
sys.exit(0)
