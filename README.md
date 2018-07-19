# Platform9 Autodeploy
Auto-Deploy is a CS-developed tool for bringing bare-metal hosts under management by a Platform9 control plane.  It can bring a host to the point where it shows up in the Clarify UI as a host waiting to be authorized, or it can (optionally) perform Platform9 role deployments for both OpenStack and Kubernetes.  Auto-Deploy includes a CLI and Web UI and can be installed on a CentOS or Ubuntu control host.

## Prerequisites
Auto-Deploy must be installed on a control host with IP connectivity to the hosts to be brought under management.  CentOS 7.4 or Ubuntu 16.04 are supported on the control host.  Before installing Auto-Deploy, you'll need administrator credentials for the Platform9 control plane.  If a proxy is required for HTTP/HTTPS traffic, you'll need the URL for the proxy.

## Installation
Perform the following steps to install Auto-Deploy:

1. Login as root on the control host (or a user with sudo access)

2. Clone the Auto-Deploy repository. 

```
git clone https://github.com/platform9/autodeploy.git /opt/autodeploy
```
NOTE: In this example, AD the installation directory is /opt/autodeploy, but any directory can be used.

3. Git Branching Strategy

By default, you'll be on the "master" branch after cloning the repository.  If you'd like to use the latest version (but perhaps not fully tested) you should checkout the "develop" branch.  If instructed to use a private branch, you'll need to checkout a specific branch.  To checkout a branch, use the following command:

```
cd /opt/autodeploy
git checkout <branchName>
```

## Configuration Control Plane (CLI Only)
To configure the Auto-Deploy CLI to communicate with the Platform9 control plane, run the following command (a sample session is included):

```
# ./deploy -s
NOTE: to enter a NULL value for prompt, enter '-'
 
Instance URL [https://sample.platform9.net]:
--> accepted: https://sample.platform9.net
 
Admin Username [user@company.com]:
--> accepted: user@company.com
 
Admin Password [********]:
--> accepted: ********
 
Region [KVM-01]:
--> accepted: KVM-01
 
Tennant [service]:
--> accepted: service
 
Manage Hostname [true false] [false]:
--> accepted: false
 
Manage DNS Resolver [true false] [false]:
--> accepted: false
 
DNS Resolver 1 [8.8.8.8]:
--> accepted: 8.8.8.8
 
DNS Resolver 2 [8.8.4.4]:
--> accepted: 8.8.4.4
 
DNS Domain for Nova Hypervisors [company.com]:
--> accepted: company.com
 
Proxy URL:
--> accepted: -
 
Ansible inventory file exists - overwrite with template? y
```

## Install Prerequisite Packages
To install prerequisite packages on the control host, run the following command (a sample session is included):

```
# ./deploy -i
--> Installation Log: ./log/pf9-autodeploy.2018-05-22_11:36:13.log
--> Validating package dependencies: epel-release ntp nginx gcc python-devel python2-pip bc shade docker-py ansible
```

## Configuration Inventory (CLI Only)
Auto-Deploy uses Ansible to execute commands on the hosts to be taken under management.  In order to configure Ansible to run remote commands on the managed hosts, the Ansible Inventory file must be configured.  This file is located in /opt/autodeploy/inventory/hosts.

NOTE: A sample template is installed in the previous command ("./deploy -s").

## Sample Inventory File
```
##
## Ansible Inventory
##
[all]
[all:vars]
ansible_ssh_pass=winterwonderland
ansible_sudo_pass=winterwonderland

################################################################################################
## Optional Settings
################################################################################################
manage_network=True
live_migration=True
nested_virt=False
kernel_same_page_merging=False

################################################################################################
## OpenStack Groups
################################################################################################
## global variables defined in group_vars/hypervisors.yml
[hypervisors]
hv01 ansible_host=10.0.0.10 ansible_user=centos ha_cluster_ip=10.0.0.10 dhcp=on snat=on
hv02 ansible_host=10.0.0.11 ansible_user=ubuntu ha_cluster_ip=10.0.0.11 dhcp=on snat=on
hv03 ansible_host=10.0.0.12 ansible_user=ubuntu ha_cluster_ip=10.0.0.12
hv04 ansible_host=10.0.0.13 ansible_user=ubuntu ha_cluster_ip=10.0.0.13

## global variables defined in group_vars/glance.yml
[glance]
hv01 glance_public_endpoint=True

## global variables defined in group_vars/cinder.yml
[cinder]
hv02 cinder_ip=10.0.0.11 pvs=["/dev/sdb","/dev/sdc","/dev/sdd","/dev/sde"]

################################################################################################
## Kubernetes Groups
################################################################################################
## global variables defined in group_vars/containervisors.yml
[k8s-master]
cv01 ansible_host=10.0.0.14 ansible_user=centos cluster_uuid=7273706d-afd5-44ea-8fbf-901ceb6bef27

[k8s-worker]
cv02 ansible_host=10.0.0.15 ansible_user=centos cluster_uuid=7273706d-afd5-44ea-8fbf-901ceb6bef27
cv03 ansible_host=10.0.0.16 ansible_user=centos cluster_uuid=7273706d-afd5-44ea-8fbf-901ceb6bef27
```

## Controlling UID/GID for the Platform9 Host Agent
If you want to control the UID and GID values for the Platform9 service account (pf9/pf9group), set the following inventory variables:
* pf9_uid
* pf9_gid

If these variables are not defined, the Host Agent Installer will allow the system to auto-assign the UID and GID.

NOTE: This feature is not idempotent.  If the 'pf9' user had not been created yet, Auto-Deploy will create the 'pf9' user and 'pf9group' group based on the values of pf9_uid and pf9_gid.  If the 'pf9' user already exists, Auto-Deploy will skip the user/group management section; it will not attempt to alter the UID/GID settings.

## Running Auto-Deploy
The basic syntax for starting Auto-Deploy includes a target (which can be a host group, individual host, or comma-delimited list of hosts) and an optional flag ('-a') that instructs it to perform role deployment.

Here's an example of invoking Auto-Deploy against a number of hosts:
```
# ./deploy hyper201,hyper202,hyper203
################################################################
# Platform9 AutoDeploy Utility
################################################################
--> Installation Log: ./log/pf9-autodeploy.2018-05-22_11:47:22.log
--> Validating package dependencies: epel-release ntp nginx gcc python-devel python2-pip bc shade docker-py ansible setupd
--> Updating setupd libraries: pf9_master_setup.py pf9_utils.py pf9_mgmt_setup.py attach-node add-cluster
--> ansible_version = 2.5
 
[Executing: ansible-playbook ./pf9-autodeploy.yml]
.
.
.
```
Here's an example of invoking Auto-Deploy against a host group and performing role deployments (based on metadata defined in /opt/autodeploy/inventory/hosts):
```
# ./deploy -a hyper201,hyper202,hyper203,hyper204
################################################################
# Platform9 AutoDeploy Utility
################################################################
--> Installation Log: ./log/pf9-autodeploy.2018-05-22_16:29:01.log
--> Validating package dependencies: epel-release ntp nginx gcc python-devel python2-pip bc shade docker-py ansible setupd
--> Updating setupd libraries: pf9_master_setup.py pf9_utils.py pf9_mgmt_setup.py attach-node add-cluster
--> ansible_version = 2.5
 
[Executing: ansible-playbook ./pf9-autodeploy.yml]
.
.
.
```
Here's the usage statement showing all command-line options:
```
# ./deploy
Usage: ./deploy [Args] <target>
 
Args (Optional):
 
-a|--autoRegister          : auto-register host with control plane
-i|--installPrereqs        : install pre-requisites and exit
-s|--setup                 : run setup and exit
-u|--ui                    : install web UI (Ansible AWX)
-r|--restartAwx            : restart AWX
-d|--dbinit                : initialize AWX database
-x|--dbExport <exportFile> : use <exportFile> for dbinit
-n|--nginx-init            : configure nginx (pf9-express config)
-c|--config <configFile>   : use custom configuration file
-e|--extra-vars <string>   : ansible extra-vars <name=val,...>
-h|--help                  : display this message
```

## Managing Multiple Cloud Controller Instances (DUs)
If you have more than one Platform9 region to manage, you can create a configuration file for each one (using pf9-autodeploy.conf as a template) and start deploy with the '-c' flag:

```
./deploy -c ~/pf9-site1.conf -a hv01
```

## Overriding Inventory Variables
If you want to override an Ansible variable defined in Inventory or dynamically within playbooks, you can invoke deploy with the '-e' flag:

```
./deploy -c ~/pf9-autodeploy.conf -a -e "proxy_url=https://proxy1.platform9.net" hv01
```
NOTE: Variables passed as extra-vars have the highest precedence.

## Auto-Deploy Web UI
Auto-Deploy includes a Web UI based on Ansibe AWX, an open-source project that provides an Rest API and Web-based interface for running Ansible playbooks, which is the underlying technology leveraged by Auto-Deploy.

To install AWX with Auto-Deploy configured within its database, run the following command:

```
# ./deploy -u -d
[ Installing Web UI (Ansible AWX) ]
--> Installation Log: /tmp/pf9-deploy.log
--> validating awx repository: present
--> installing tower-cli
--> installing awx (this will take a while - monitor log for status)
--> waiting for awx to initialize

[ Installing AWX Database ]
--> copying default database
--> importing default database
--> restarting AWX
```

## Accessing Auto-Deploy Web UI
To login to the Web UI (AWX), point your browser at the IP address of your Auto-Deploy control host (using the default port of 80).

NOTE: The default username is "admin"; the default password is "password".

## Accessing the Auto-Deploy Rest API
To access the API, point your browser (or API client application) at the IP address of your control host and append /api/v1/.

For example, http://<ip_address>/api/v1/

## License

Commerical

