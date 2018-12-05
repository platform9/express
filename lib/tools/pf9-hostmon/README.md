A script to monitor cpu utilization accross instances using Gnocchi metrics.

# Installation Instructions (Ubuntu 16.04)
* apt-get update
* apt-get install python-dev python-pip
* pip install python-openstackclient
* pip install gnocchiclient
* pip install plotly
* pip install psutil
* apt-get install npm
* curl -sL https://deb.nodesource.com/setup_10.x | sudo bash -
* apt-get install nodejs
* npm install -g electron@1.8.4 orca
* apt-get install xvfb
* 
* 
* 
* 
* 
* 
* 
* 
* 
* 

# Installation Instructions (CentOS-7)
* yum install -y epel-release gcc gcc openssl-devel python-devel python-pip
* yum install -y python-pip
* yum install -y npm
* pip install --upgrade pip' command
* pip install python-openstackclient
* pip install gnocchiclient
* pip install plotly
* pip install psutil
* npm install -g electron@1.8.4 orca
* yum install -y gtk2
* yum install -y GConf2
* yum install -y libXtst
* yum install -y libXScrnSaver
* yum install -y alsa-lib
* yum install -y pango pango-devel
* pip install conda
* yum install -y bzip2
* curl -O https://repo.anaconda.com/miniconda/Miniconda2-latest-Linux-x86_64.sh
* bash Miniconda2-latest-Linux-x86_64.sh
* conda install numpy
* conda install -c plotly plotly-orca

# Sample Cron Entry
0 6 * * * (/opt/express/lib/tools/pf9-hostmon/call_hostpeaks.sh /root/openstack-ebsco-pdc.rc PDC && /opt/express/lib/tools/pf9-hostmon/call_hostpeaks.sh /root/openstack-ebsco-sdc.rc SDC) >> /var/log/pf9-hostpeaks.log 2>&1

# Sample pipeline.yaml (DU)
```
---
sources:
    - name: memory_source
      interval: 600
      meters:
          - "memory.usage"
          - "memory"
      sinks:
          - memory_sink
    - name: memory_store
      interval: 600
      meters:
          - "memory.usage"
          - "memory"
      sinks:
          - meter_sink
    - name: memory_util_meter
      interval: 600
      meters:
          - "memory_util"
      sinks:
          - meter_sink
    - name: cpu_to_cpu_util_meter
      interval: 600
      meters:
          - "cpu"
      sinks:
          - cpu_sink
    - name: cpu_util_meter
      interval: 600
      meters:
          - "cpu_util"
      sinks:
          - meter_sink
    - name: pf9_service_state_src
      interval: 600
      meters:
          - "pf9.services.bbmaster.status"
          - "pf9.services.janitor.status"
          - "pf9.services.nova.api.status"
          - "pf9.services.nova.conductor.status"
          - "pf9.services.nova.network.status"
          - "pf9.services.nova.scheduler.status"
      sinks:
          - meter_sink
    - name: host_cpu_meter
      interval: 300
      meters:
          - "pf9.host.cpu.usage"
      sinks:
          - meter_sink
    - name: host_memory_meter
      interval: 300
      meters:
          - "pf9.host.memory.usage"
      sinks:
          - meter_sink
    - name: host_root_disk_meter
      interval: 300
      meters:
          - "pf9.host.root.disk.usage"
      sinks:
          - meter_sink
    - name: host_instance_disk_meter
      interval: 300
      meters:
          - "pf9.host.instance.disk.usage"
      sinks:
          - meter_sink
sinks:
    - name: meter_sink
      transformers:
      publishers:
          - direct://?dispatcher=database
          - direct://?dispatcher=gnocchi
    - name: memory_sink
      transformers:
          - name: "arithmetic"
            parameters:
                target:
                    name: "memory_util"
                    unit: "%"
                    type: "gauge"
                    scale: "100 * $(memory.usage) / $(memory)"
      publishers:
          - direct://?dispatcher=database
          - direct://?dispatcher=gnocchi
    - name: cpu_sink
      transformers:
          - name: "rate_of_change"
            parameters:
                target:
                    name: "cpu_util"
                    unit: "%"
                    type: "gauge"
                    scale: "100.0 / (10**9 * (resource_metadata.cpu_number or 1))"
      publishers:
          - direct://?dispatcher=database
          - direct://?dispatcher=gnocchi
```

# Sample pipeline.yaml (KVM Host)
```
---
sources:
    - name: memory_usage_meter
      interval: 300
      meters:
          - "memory.usage"
      sinks:
          - meter_sink
    - name: cpu_to_cpu_util_meter
      interval: 600
      meters:
          - "cpu"
      sinks:
          - cpu_sink
    - name: cpu_util_meter
      interval: 600
      meters:
          - "cpu_util"
      sinks:
          - meter_sink
    - name: pf9_service_state_src
      interval: 600
      meters:
          - "pf9.services.bbmaster.status"
          - "pf9.services.janitor.status"
          - "pf9.services.nova.api.status"
          - "pf9.services.nova.conductor.status"
          - "pf9.services.nova.network.status"
          - "pf9.services.nova.scheduler.status"
      sinks:
          - meter_sink
    - name: host_cpu_meter
      interval: 300
      meters:
          - "pf9.host.cpu.usage"
      sinks:
          - meter_sink
    - name: host_memory_meter
      interval: 300
      meters:
          - "pf9.host.memory.usage"
      sinks:
          - meter_sink
    - name: host_root_disk_meter
      interval: 300
      meters:
          - "pf9.host.root.disk.usage"
      sinks:
          - meter_sink
    - name: host_instance_disk_meter
      interval: 300
      meters:
          - "pf9.host.instance.disk.usage"
      sinks:
          - meter_sink
sinks:
    - name: meter_sink
      transformers:
      publishers:
          - direct://?dispatcher=database
          - direct://?dispatcher=gnocchi
    - name: cpu_sink
      transformers:
          - name: "rate_of_change"
            parameters:
                target:
                    name: "cpu_util"
                    unit: "%"
                    type: "gauge"
                    scale: "100.0 / (10**9 * (resource_metadata.cpu_number or 1))"
      publishers:
          - direct://?dispatcher=database
          - direct://?dispatcher=gnocchi
```
