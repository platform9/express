# Platform9 Express

Platform9 Express (**pf9-express**) is a Customer Success developed tool for bringing hosts under management by a Platform9 management plane.  It can bring a host to the point where it shows up in the Clarity UI as a host waiting to be authorized, or it can (optionally) perform Platform9 role deployments for both OpenStack and Kubernetes.  Platform9 Express includes a CLI and can be installed on a CentOS or Ubuntu control host.

### Table of Contents

- [Prerequisites](#prerequisites)
- [Installing Express on Control Host](#installation)
- [Configuring Access to the Management Plane](#configure-access-to-the-management-plane-cli-only)
- [Install Prerequisite Packages on Control Host](#install-prerequisite-packages)
- [Configuring the Inventory](#configuring-the-inventory-cli-only)
- [CSV Import](#csv-import)
- [Running Platform9 Express](#running-platform9-express)

#### Advanced Topics

- [Overriding Variables](#overriding-inventory-variables)
- [Using SR-IOV](docs/SRIOV.md)

## Prerequisites

Platform9 Express must be installed on a control host with IP connectivity to the hosts to be brought under management. CentOS 7.4+, Ubuntu 16.04, or Ubuntu 18.04 are supported on the control host.  Before installing Platform9 Express, you'll need administrator credentials for the Platform9 management plane.  If a proxy is required for HTTP/HTTPS traffic, you'll need the URL for the proxy.

> There are strict requirements for hosts whose software is deployed by Platform9 Express. Please refer to your Customer Success team for further details.

## Installation

Perform the following steps to install Platform9 Express:

1. Login as **root** (or a user with sudo access) on the host that you plan to install Platform9 Express on.

2. Install **git**

```
yum install git # CentOS

apt update && apt install git # Ubuntu
```

3. Clone the Platform9 Express repository.

```
git clone https://github.com/platform9/express.git /opt/pf9-express
```

> In this example, the installation directory is **/opt/pf9-express**, but any directory can be used.

## Configure Access to the Management Plane (CLI Only)

To configure the Platform9 Express CLI to communicate with the Platform9 management plane, run the following command:

```
./pf9-express -s
```

Example:

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

To install prerequisite packages on the Platform9 Express control host, run the following command:

```
./pf9-express -i
```

Example:

```
# ./pf9-express -i
--> Installation Log: ./log/pf9-express.2018-05-22_11:36:13.log
--> Validating package dependencies: epel-release ntp nginx gcc python-devel python2-pip bc shade docker-py ansible
```

## Configuring the Inventory (CLI Only)

Platform9 Express uses Ansible to execute commands on the hosts to be taken under management.  In order to configure Ansible to run remote commands on the managed hosts, the Ansible Inventory file must be configured.  This file is located in **/opt/pf9-express/inventory/hosts**.

> Platform9 Express supports Ansible's `group_vars` and `host_vars` methods of defining variables.

A sample template is installed in the setup command (**./pf9-express -s**). A breakdown of the inventory file is below:

## Sample Inventory File Part 1 - Authentication Portion

This is where you enter the credentials for your control host to log into the target hosts to be managed by the Platform9 management plane.

> When using password authentication, comment out `ansible_ssh_private_key_file`. When using a private key, comment out `ansible_sudo_pass`.

```
##
## Ansible Inventory
##
[all]
[all:vars]
ansible_user=ubuntu
ansible_sudo_pass=winterwonderland
ansible_ssh_pass=winterwonderland
#ansible_ssh_private_key_file=~/.ssh/id_rsa
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

This is where you can configure your Kubernetes cluster members under their own roles (either master or worker). For a worker, you can optionally add it into a running cluster using the **cluster_uuid** variable. For any new workers, you can omit this variable assignment.

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

Instead of manually configuring the inventory file, you can use the **-f <csvFile>** option to auto-configure it from a CSV definition file.

Here's a sample CSV definition file:

```
hostname,username,key,ip,dhcp,snat,glance,glance-public,nic1,nic2,mgmtvlan,mgmtip,mgmtnetmask,Storagevlan,storageip,storagenetmask,tunnelvlan,tunnelip,tunnelnetmask
fake01,centos,~/.ssh/id_rsa,172.16.7.182,TRUE,TRUE,TRUE,TRUE,ens160,,243,172.16.243.11,255.255.255.0,244,172.16.244.11,255.255.255.0,245,172.16.245.11,255.255.255.0
fake02,ubuntu,~/.ssh/id_rsa,172.16.7.47,TRUE,FALSE,FALSE,FALSE,ens192,,243,172.16.243.12,255.255.255.0,244,172.16.244.12,255.255.255.0,245,172.16.245.12,255.255.255.0
```

## Controlling UID/GID for the Platform9 Host Agent

If you want to control the UID and GID values for the Platform9 service account (pf9:pf9group), set the following inventory variables:

* pf9_uid
* pf9_gid

If these variables are not defined, the Host Agent Installer will allow the system to auto-assign the UID and GID.

> This feature is not idempotent.  If the **pf9** user had not been created yet, Platform9 Express will create the **pf9** user and **pf9group** group based on the values of **pf9_uid** and **pf9_gid**.  If the **pf9** user already exists, Platform9 Express will skip the user/group management section; it will not attempt to alter the UID/GID settings.

## Running Platform9 Express

The basic syntax for starting Platform9 Express includes a target (host group, individual host, comma-delimited list of hosts, or "all" to run all groups) and an optional flag (**-a**) that instructs it to perform role deployment.

Here's an example of invoking Platform9 Express against a number of hosts without registering them automatically to the management plane:

```
# ./pf9-express hv01,hv02,hv03
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

Here's an example of invoking Platform9 Express against a single host group (host groups are either "pmo" for OpenStack and "pmk" for Kubernetes), performing role deployments (based on metadata defined in **/opt/pf9-express/inventory/hosts**), and registering them automatically to the management plane

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

Here's an example of invoking Platform9 Express against all host groups and performing role deployments (based on metadata defined in **/opt/pf9-express/inventory/hosts**):

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
-v|--inventory <file>      : use alternate inventory file for Ansible
-h|--help                  : display this message
```


If you have more than one Platform9 region to manage, you can create a configuration file for each one (using pf9-express.conf as a template) and start **pf9-express** with the **-c** flag:

```
./pf9-express -c ~/pf9-site1.conf -a hv01
```

## Overriding Inventory Variables

If you want to override an Ansible variable defined in Inventory or dynamically within playbooks, you can invoke **pf9-express** with the **-e** flag:

```
./pf9-express -c ~/pf9-express.conf -a -e "proxy_url=https://proxy1.platform9.net" hv01
```

> Variables passed as extra-vars have the highest precedence.

## License

Apache 2.0
