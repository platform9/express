# Platform9 Autodeploy
Autodeploy aims to automate the prerequisite tasks required to bring OpenStack hypervisors and Kubernetes containervisors under management by a Platform9 control plane, including package/service prerequisites, host agent(s), and control plane authorization.

GitHub Repository : [https://github.com/platform9/autodeploy.git](https://github.com/platform9/autodeploy.git)

## Installation/Setup Instructions

**Step 1 : Run Setup**
```
$ ./INSTALL -s
Instance URL: https://acme.platform9.net
--> accepted: https://acme.platform9.net

Admin Username: admin-user@platform9.net
--> accepted: admin-user@platform9.net

Admin Password: ---masked---
--> accepted: ---masked---

Region: master
--> accepted: master

Tenant [service]: admin
--> accepted: admin

Manage Hostname [true false] [false]:
--> accepted: false

Manage DNS Resolver [true false] [false]:
--> accepted: false

DNS Resolver 1 [8.8.8.8]:
--> accepted: 8.8.8.8

DNS Resolver 2 [8.8.4.4]:
--> accepted: 8.8.4.4

DNS Domain for Nova Hypervisors: cs.platform9.net
--> accepted: cs.platform9.net

Proxy URL:
--> accepted: -
```

**Step 2 : Configure Your Inventory**
* vi inventory/hosts 

NOTE: The above file is a sample starting point, with a reference configuration for both OpenStack and Kubernetes. You'll need change the hostnames and IP addresses to reflect your environment.

* Ansible Inventory Example
```
##
## Ansible Inventory
##
[all]
[all:vars]
ansible_ssh_pass=Pl@tform9
ansible_sudo_pass=Pl@tform9

################################################################################################
## Openstack Groups
################################################################################################
## global variables defined in group_vars/hypervisors.yml
[hypervisors]
hv10 ansible_host=172.16.7.172 ansible_user=centos ha_cluster_ip=172.16.7.172 dhcp=on snat=on glance=on
hv11 ansible_host=172.16.7.171 ansible_user=ubuntu ha_cluster_ip=172.16.7.171

## global variables defined in group_vars/glance.yml
[glance]
hv10

################################################################################################
## Kubernetes Groups
################################################################################################
## global variables defined in group_vars/containervisors.yml
[containervisors]
cv01 ansible_host=172.16.7.116 ansible_user=centos cluster_name=c1 cluster_fqdn=c1.platform9.netcv02 ansible_host=172.16.7.88 ansible_user=centos cluster_name=c1 cluster_fqdn=c1.platform9.net
```

**Step 3: Run Autodeploy**
* ./INSTALL [-a] \<target\>

Where '\<target\>' is a hostname or group defined in Inventory file.

NOTE: if you include the '-a' flag, Autodeploy will perform pre-authorization and role deployment for the hypervisor or containervisor.

## Usage Notes
Here's the usage statement for the Autodeploy installer:
```
$ ./INSTALL
Usage: ./INSTALL [Args] <target>

Args (Optional):

-a|--autoRegister        : auto-register host with control plane
-i|--installPrereqs      : install pre-requisites and exit
-s|--setup               : run setup and exit
-c|--config <configFile> : use custom configuration file
-e|--extra-vars <string> : ansible extra-vars <name=val,...>
-h|--help                : display this message
```

**Managing Multiple DUs**
If you have more than one Platform9 region to manage, you can create a configuration file for each one (using pf9-autodeploy.conf as a template) and start INSTALL with the '-c' flag:
```
./INSTALL -c ~/pf9-site1.conf -a hv01
```

**Overriding Inventory Variable**
If you want to override an Ansible variable defined in Inventory or dynamically within playbooks, you can invoke INSTALL with the '-e' flag:
```
./INSTALL -c ~/pf9-autodeploy.conf -a -e "proxy_url=https://proxy1.platform9.net" hv01
```
NOTE: Variables passed as extra-vars have the highest precedence.

## License

Commerical

