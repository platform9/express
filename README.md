# Platform9 Express
Platform9 Express (pf9-express) is a Customer Success developed tool for bringing hosts under management by a Platform9 management plane.  It can bring a host to the point where it shows up in the Clarity UI as a host waiting to be authorized, or it can (optionally) perform Platform9 role deployments for both OpenStack and Kubernetes.  Platform9 Express includes a CLI and can be installed on a CentOS or Ubuntu control host.

## Prerequisites
Platform9 Express must be installed on a control host with IP connectivity to the hosts to be brought under management. CentOS 7.8+, Ubuntu 18.04, 20.04, or Rocky 9.x are supported.  Before installing Platform9 Express, you'll need administrator credentials for the Platform9 management plane.  If a proxy is required for HTTP/HTTPS traffic, you'll need the URL for the proxy.

### Python3

Python3 is now required for playbook execution and will be installed automatically on the control host.
If you have a specific version of python that should be executed on the _remote_ hosts, you can set these two lines accordingly.

```
[defaults]
### Set the following two lines if you have python2 installed
interpreter_python=/bin/python3
ansible_python_interpreter=/bin/python3
###
```

## Installation
Perform the following steps to install Platform9 Express:

1. Login as root (or a user with sudo access) on the host that you plan to install Platform9 Express on.

2. Install git
```
yum install git # CentOS

apt update && apt install git # Ubuntu

dnf install git # Rocky
```

3. Clone the Platform9 Express repository.

```
git clone https://github.com/platform9/express.git /opt/pf9-express && cd /opt/pf9-express
```
**NOTE:** In this example, the installation directory is /opt/pf9-express, but any directory can be used.

## Configure Access to the Management Plane (CLI Only)
To configure the Platform9 Express CLI to communicate with the Platform9 management plane, run the following command (a sample session is included):

```
# ./pf9-express -s
NOTE: to enter a NULL value for prompt, enter '-'

PF9 Management Plane URL [https://company.platform9.net]:
--> accepted: https://company.platform9.net

Admin Username [user@company.com]:
--> accepted: user@company.com

Admin Password [********]:
--> accepted: ********

Region [Sunnyvale]:
--> accepted: Sunnyvale

Tenant [service]:
--> accepted: service

Manage Hostname [true false] [false]:
--> accepted: false

Manage DNS Resolver [true false] [false]:
--> accepted: false

DNS Resolver 1 [8.8.8.8]:
--> accepted: 8.8.8.8

DNS Resolver 2 [8.8.4.4]:
--> accepted: 8.8.4.4

Proxy URL:
--> accepted: -
```

## Install Prerequisite Packages
To install prerequisite packages on the Platform9 Express control host, run the following command (a sample session is included):

```
# [root@pf9-express]# ./pf9-express -i
Found release 7.9.2009 on platform centos
--> Installing Prerequisites
--> Installation Log: ./log/pf9-express.2023-06-01_20:50:31.log
--> Validating package dependencies: epel-release ntp nginx gcc python3-devel python3-pip jq bc pbr openstacksdk==0.62.0 docker-py pyopenssl ansible-python3
```

**NOTE:** As you can see, python3 based stack will be installed. If your system already has python2, you will need to refer to [the Python3](#python3) section above.

## Configuration Inventory (CLI Only)
Platform9 Express uses Ansible to execute commands on the hosts to be taken under management.  In order to configure Ansible to run remote commands on the managed hosts, the Ansible Inventory file must be configured.

**NOTE:** A sample template is installed in the previous command ("./pf9-express -s").
This file is located in `/opt/pf9-express/inventory/hosts`.

A breakdown of the Inventory File is below:

## Sample Inventory File Part 1 - Authentication Portion
This is where you enter the credentials for your control host to log into the target VM hosts to be managed by the Platform9 management plane (through either a password or SSH key, comment out any password lines if using SSH authentication and vice versa as needed)
```
##
## Ansible Inventory
##
[all]
[all:vars]
# The remote user ansible will use for ssh execution
ansible_user=ubuntu
ansible_sudo_pass=winterwonderland
ansible_ssh_pass=winterwonderland
# The ssh key for the ssh connection to the `ansible_user` on the remote host
ansible_ssh_private_key_file=~/.ssh/id_rsa
```

## Sample Inventory File Part 2 - Network Portion
This is where you can configure optional network settings to create a bond with single or multiple interfaces.
```
################################################################################################
## Optional Settings
################################################################################################
manage_network=True
bond_ifname=bond0
bond_mode=1
bond_mtu=9000

## network bond configuration implemented if manage_network=True
[bond_config]
## for single interface bond configuration
hv01 bond_members='eth1' bond_sub_interfaces='[{"vlanid":"100","ip":"10.0.0.11","mask":"255.255.255.0"}]'

## for multiple interface bond configuration
hv02 bond_members='["eth1","eth2"]' bond_sub_interfaces='[{"vlanid":"100","ip":"10.0.0.12","mask":"255.255.255.0"}]'
hv03 bond_members='["eth1","eth2"]' bond_sub_interfaces='[{"vlanid":"100","ip":"10.0.0.13","mask":"255.255.255.0"}]'
cv01 bond_members='["eth1","eth2"]' bond_sub_interfaces='[{"vlanid":"100","ip":"10.0.0.15","mask":"255.255.255.0"}]'
```

## Sample Inventory File Part 3 - OpenStack Portion
You can configure the OpenStack hosts and their pertinent roles (Hypervisor, Image Host, Storage Host, DNS Host)
```
################################################################################################
## OpenStack Groups
################################################################################################
[pmo:children]
hypervisors
glance
cinder

## global variables defined in group_vars/hypervisors.yml
## note: if the following variables are not defined, the value of ansible_host will be inherited
##   - vm_console_ip
##   - ha_cluster_ip
##   - tunnel_ip
[hypervisors]
hv01 ansible_host=10.0.0.11 vm_console_ip=10.0.0.11 ha_cluster_ip=10.0.1.11 tunnel_ip=10.0.2.11 dhcp=on snat=on
hv02 ansible_host=10.0.0.12 vm_console_ip=10.0.0.12 tunnel_ip=10.0.2.12 dhcp=on snat=on
hv03 ansible_host=10.0.0.13 vm_console_ip=10.0.0.13 tunnel_ip=10.0.2.13
hv04 ansible_host=10.0.0.14

## global variables defined in group_vars/glance.yml
## note: if the following variables are not defined, the value of ansible_host will be inherited
##   - glance_ip
[glance]
hv01 glance_ip=10.0.3.11 glance_public_endpoint=True
hv02 glance_ip=10.0.3.12

## global variables defined in group_vars/cinder.yml
## note: if the following variables are not defined, the value of ansible_host will be inherited
##   - cinder_ip
[cinder]
hv02 cinder_ip=10.0.4.14 pvs=["/dev/sdb","/dev/sdc","/dev/sdd","/dev/sde"]

## global variables defined in group_vars/designate.yml
## note: this role must be enabled by Platform9 Customer Success before using
[designate]
#hv01
```

## Sample Inventory File Part 4 - Kubernetes Portion
This is where you can configure your Kubernetes cluster members under their own roles (either master or worker). For a worker, you can optionally add it into a running cluster using the "cluster_uuid" variable. For any new workers, you can omit this variable assignment.
```
################################################################################################
## Kubernetes Groups
################################################################################################
[pmk:children]
k8s_master
k8s_worker

## global variables defined in group_vars/containervisors.yml
## note: if the following variables are not defined, their tasks will be skipped
##   - cluster_uuid
[k8s_master]
cv01 ansible_host=10.0.0.15
cv02 ansible_host=10.0.0.16
cv03 ansible_host=10.0.0.17

[k8s_worker]
cv04 ansible_host=10.0.0.18 cluster_uuid=7273706d-afd5-44ea-8fbf-901ceb6bef27
cv05 ansible_host=10.0.0.19 cluster_uuid=7273706d-afd5-44ea-8fbf-901ceb6bef27
```

## CSV Import
Instead of manually configuring the inventory file, you can use the '-f <csvFile>' option to auto-configure it from a CSV definition file.

Here's a sample CSV definition file:
```
hostname,username,key,ip,dhcp,snat,glance,glance-public,nic1,nic2,mgmtvlan,mgmtip,mgmtnetmask,Storagevlan,storageip,storagenetmask,tunnelvlan,tunnelip,tunnelnetmask
fake01,centos,~/.ssh/id_rsa,172.16.7.182,TRUE,TRUE,TRUE,TRUE,ens160,,243,172.16.243.11,255.255.255.0,244,172.16.244.11,255.255.255.0,245,172.16.245.11,255.255.255.0
fake02,ubuntu,~/.ssh/id_rsa,172.16.7.47,TRUE,FALSE,FALSE,FALSE,ens192,,243,172.16.243.12,255.255.255.0,244,172.16.244.12,255.255.255.0,245,172.16.245.12,255.255.255.0
```

## Controlling UID/GID for the Platform9 Host Agent
If you want to control the UID and GID values for the Platform9 service account (pf9/pf9group), set the following inventory variables:
* pf9_uid
* pf9_gid

If these variables are not defined, the Host Agent Installer will allow the system to auto-assign the UID and GID.

NOTE: This feature is not idempotent.  If the 'pf9' user had not been created yet, Platform9 Express will create the 'pf9' user and 'pf9group' group based on the values of pf9_uid and pf9_gid.  If the 'pf9' user already exists, Platform9 Express will skip the user/group management section; it will not attempt to alter the UID/GID settings.

## Running Platform9 Express
The basic syntax for starting Platform9 Express includes a target (host group, individual host, comma-delimited list of hosts, or "all" to run all groups) and an optional flag ('-a') that instructs it to perform role deployment.

Here's an example of invoking Platform9 Express against a number of hosts without registering them automatically to the management plane:

```
[root@pf9-express]# ./pf9-express -g -a -b centos03
Found release 7.9.2009 on platform centos
################################################################
# Platform9 Express Utility
################################################################

[Executing: ansible-playbook ./pf9-express.yml]
ansible-playbook-3 2.9.27
  config file = /opt/pf9-express/ansible.cfg
  configured module search path = ['/root/.ansible/plugins/modules', '/usr/share/ansible/plugins/modules']
  ansible python module location = /usr/lib/python3.6/site-packages/ansible
  executable location = /bin/ansible-playbook-3
  python version = 3.6.8 (default, Nov 16 2020, 16:55:22) [GCC 4.8.5 20150623 (Red Hat 4.8.5-44)]
Using /opt/pf9-express/ansible.cfg as config file
host_list declined parsing /opt/pf9-express/inventory/hosts as it did not pass its verify_file() method
script declined parsing /opt/pf9-express/inventory/hosts as it did not pass its verify_file() method
```

Here's an example of invoking Platform9 Express against a number of hosts without registering them automatically to the management plane:

```
# ./pf9-express -g -a -b hv01,hv02,hv03
################################################################
# Platform9 Express Utility
################################################################
--> Installation Log: ./log/pf9-express.2018-05-22_11:47:22.log
--> Validating package dependencies: epel-release ntp nginx gcc python-devel python2-pip bc shade docker-py ansible setupd
--> Updating setupd libraries: pf9_master_setup.py pf9_utils.py pf9_mgmt_setup.py attach-node add-cluster
--> ansible_version = 2.5

[Executing: ansible-playbook ./pf9-express.yml]
.
.
.
```

Here's an example of invoking Platform9 Express against a single host group (host groups are either "pmo" for OpenStack and "pmk" for Kubernetes), performing role deployments (based on metadata defined in /opt/pf9-express/inventory/hosts), and registering them automatically to the management plane
```
# ./pf9-express -a pmk
################################################################
# Platform9 Express Utility
################################################################
--> Installation Log: ./log/pf9-express.2018-05-22_16:29:01.log
--> Validating package dependencies: epel-release ntp nginx gcc python-devel python2-pip bc shade docker-py ansible setupd
--> Updating setupd libraries: pf9_master_setup.py pf9_utils.py pf9_mgmt_setup.py attach-node add-cluster
--> ansible_version = 2.5

[Executing: ansible-playbook ./pf9-express.yml]
.
.
.
```
Here's an example of invoking Platform9 Express against all host groups and performing role deployments (based on metadata defined in /opt/pf9-express/inventory/hosts):
```
# ./pf9-express -a all
################################################################
# Platform9 Express Utility
################################################################
--> Installation Log: ./log/pf9-express.2018-05-22_16:29:01.log
--> Validating package dependencies: epel-release ntp nginx gcc python-devel python2-pip bc shade docker-py ansible setupd
--> Updating setupd libraries: pf9_master_setup.py pf9_utils.py pf9_mgmt_setup.py attach-node add-cluster
--> ansible_version = 2.5

[Executing: ansible-playbook ./pf9-express.yml]
.
.
.
```
Here's the usage statement showing all command-line options:
```
# ./pf9-express
Usage: ./pf9-express [Args] <target>

Args (Optional):

-a|--autoRegister          : auto-register host with management plane
-i|--installPrereqs        : install pre-requisites and exit
-s|--setup                 : run setup and exit
-o|--oscli                 : install OpenStack CLI
-c|--config <configFile>   : use custom configuration file
-e|--extra-vars <string>   : ansible extra-vars <name=val,...>
-b|--bypassPrereqs         : bypass pre-requisites
-d|--deauth                : de-authorize host
-l|--log                   : Log output file. Assumes parent directory already exists.
-u|--upgradeK8s            : upgrade Kubernetes nodes
-v|--inventory <file>      : use alternate inventory file for Ansible
-g|--debug                 : use extra ansible verbosity for debugging
-f|--csvFile <file>        : import CSV file
-t|--tag <tag[,<tag>]>     : available tags = [live-migration, image-import]
-h|--help                  : display this message
```

## Managing Multiple Cloud Management Regions (DUs)
If you have more than one Platform9 region to manage, you can create a configuration file for each one (using pf9-express.conf as a template) and start pf9-express with the '-c' flag:

```
./pf9-express -c ~/pf9-site1.conf -a hv01
```

## Overriding Inventory Variables
If you want to override an Ansible variable defined in Inventory or dynamically within playbooks, you can invoke pf9-express with the '-e' flag:

```
./pf9-express -c ~/pf9-express.conf -a -e "proxy_url=https://proxy1.platform9.net" hv01
```
NOTE: Variables passed as extra-vars have the highest precedence.


## Troubleshooting

**Issue:**

```
[root@sn-n1 express]# ./pf9-express -i
Found release 7.9.2009 on platform centos
--> Installing Prerequisites
--> Installation Log: ./log/pf9-express.2023-06-07_10:14:56.log
--> Validating package dependencies: sshpass epel-release gcc python3-devel python3-pip jq ansible==2.9.27 openstacksdk==0.62.0
ERROR: failed to install ansible==2.9.27 openstacksdk==0.62.0 - here's the last 10 lines of the log:

    return self._prepare_linked_requirement(req, parallel_builds)
  File "/usr/local/lib/python3.6/site-packages/pip/_internal/operations/prepare.py", line 528, in _prepare_linked_requirement
    link, req.source_dir, self._download, self.download_dir, hashes
  File "/usr/local/lib/python3.6/site-packages/pip/_internal/operations/prepare.py", line 223, in unpack_url
    unpack_file(file.path, location, file.content_type)
  File "/usr/local/lib/python3.6/site-packages/pip/_internal/utils/unpacking.py", line 247, in unpack_file
    untar_file(filename, location)
  File "/usr/local/lib/python3.6/site-packages/pip/_internal/utils/unpacking.py", line 218, in untar_file
    with open(path, "wb") as destfp:
UnicodeEncodeError: 'ascii' codec can't encode character '\xe9' in position 112: ordinal not in range(128)
```

**Fix:**

Create `/etc/profile.d/my-custom.lang.sh` Add following lines to it. Then `chmod a+x /etc/profile.d/my-custom.lang.sh ; source /etc/profile.d/my-custom.lang.sh`

```
export LANG=en_US.UTF-8
export LANGUAGE=en_US.UTF-8
export LC_COLLATE=C
export LC_CTYPE=en_US.UTF-8
```

On Rocky Linux 9.1 you may need to install langpacks-en glibc-all-langpacks first. Verify that locale en_US.UTF-8 is installed.

```
# localectl set-locale LANG=en_US.UTF-8
Failed to issue method call: Locale en_US.UTF-8 not installed, refusing.
```

In such event install the locale by running

```
# dnf install langpacks-en glibc-all-langpacks -y
```

## License

Apache 2.0
