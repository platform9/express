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
