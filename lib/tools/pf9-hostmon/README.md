A script to monitor cpu utilization accross instances using Gnocchi metrics.

# Installation Instructions (Ubuntu 16.04)
* apt-get install python-dev python-pip
* pip install --upgrade pip
* pip install python-openstackclient
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
