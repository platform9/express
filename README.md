# Platform9 Autodeplopy
Autodeploy aims to automate the prerequisite tasks required to bring Openstack hypervisors and Kubernetes containervisors under management by a Platform9 control plane, including package/service prerequisites, host agent(s), and control plane authorization.

GitHub Repository : [https://github.com/platform9/autodeploy.git](https://github.com/platform9/autodeploy.git)

## Installation/Setup Instructions

**Step 1 : Define SSH connection details for hypervisors**
* vi inventory/hosts

**Step 2: Run Auto-Deploy**
* ./INSTALL [-a] \<target\>

Where '\<target\>' is a hostname or group defined in Ansible inventory file.

NOTE: if you include the '-a' flag, Autodeploy will perform pre-authorization and role deployment for the hypervisor or containervisor.

The first time you run ./INSTALL it will prompt you for various settings related to the Platform9 Control Plane.  If you need to change any settings after the initial run, you can use './INSTALL -s' to re-enter any values.

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

## License

Commerical
