##
## Ansible Inventory
## 
## NOTE: As of Ansible 2.8+, inventory names should not contain hyphens.
##
[all]
[all:vars]
ansible_user=ubuntu
ansible_sudo_pass=winterwonderland
ansible_ssh_pass=winterwonderland
#ansible_ssh_private_key_file=~/.ssh/id_rsa

################################################################################################
## Optional Settings
################################################################################################
manage_network=True
bond_ifname=bond0
bond_mode=1
bond_mtu=9000

## network bond configuration implemented if manage_network=True
[bond-config]
## for single interface bond configuration
hv01 bond_members='eth1' bond_sub_interfaces='[{"vlanid":"100","ip":"10.0.0.11","mask":"255.255.255.0"}]'

## for multiple interface bond configuration
hv02 bond_members='["eth1","eth2"]' bond_sub_interfaces='[{"vlanid":"100","ip":"10.0.0.12","mask":"255.255.255.0"}]'
hv03 bond_members='["eth1","eth2"]' bond_sub_interfaces='[{"vlanid":"100","ip":"10.0.0.13","mask":"255.255.255.0"}]'
cv01 bond_members='["eth1","eth2"]' bond_sub_interfaces='[{"vlanid":"100","ip":"10.0.0.15","mask":"255.255.255.0"}]'

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
