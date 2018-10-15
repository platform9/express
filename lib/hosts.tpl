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
bond_ifname=bond0
bond_mode=1
bond_mtu=9000

## network configuration for bond (implemented if manage_network=True)
[bond-config]
hv01 bond_members='["eth1","eth2"]' bond_sub_interfaces='[{"vlanid":"100","ip":"10.0.0.11","mask":"255.255.255.0"}]'
hv02 bond_members='["eth1","eth2"]' bond_sub_interfaces='[{"vlanid":"100","ip":"10.0.0.12","mask":"255.255.255.0"}]'
cv01 bond_members='["eth1","eth2"]' bond_sub_interfaces='[{"vlanid":"100","ip":"10.0.0.15","mask":"255.255.255.0"}]'

################################################################################################
## OpenStack Groups
################################################################################################
[pmo:children]
hypervisors
glance
cinder

## global variables defined in group_vars/hypervisors.yml
## note: the following variables, if not defined, inherit the value of ansible_host
##   - vm_console_ip
##   - ha_cluster_ip
##   - tunnel_ip
[hypervisors]
hv01 ansible_host=10.0.0.11 ansible_user=centos vm_console_ip=10.0.0.11 ha_cluster_ip=10.0.1.11 tunnel_ip=10.0.2.11 dhcp=on snat=on
hv02 ansible_host=10.0.0.12 ansible_user=centos vm_console_ip=10.0.0.12 tunnel_ip=10.0.2.12 dhcp=on snat=on
hv03 ansible_host=10.0.0.13 ansible_user=ubuntu vm_console_ip=10.0.0.13 tunnel_ip=10.0.2.13
hv04 ansible_host=10.0.0.14 ansible_user=ubuntu

## global variables defined in group_vars/glance.yml
[glance]
hv01 glance_ip=10.0.3.11 glance_public_endpoint=True
hv02 glance_ip=10.0.3.12

## global variables defined in group_vars/cinder.yml
## note: the following variables, if not defined, inherit the value of ansible_host
##   - cinder_ip
[cinder]
hv02 cinder_ip=10.0.4.14 pvs=["/dev/sdb","/dev/sdc","/dev/sdd","/dev/sde"]

################################################################################################
## Kubernetes Groups
################################################################################################
[pmk:children]
k8s-master
k8s-worker

## global variables defined in group_vars/containervisors.yml
[k8s-master]
cv01 ansible_host=10.0.0.15 ansible_user=ubuntu cluster_uuid=7273706d-afd5-44ea-8fbf-901ceb6bef27

[k8s-worker]
cv02 ansible_host=10.0.0.16 ansible_user=ubuntu cluster_uuid=7273706d-afd5-44ea-8fbf-901ceb6bef27
cv03 ansible_host=10.0.0.17 ansible_user=ubuntu cluster_uuid=7273706d-afd5-44ea-8fbf-901ceb6bef27
