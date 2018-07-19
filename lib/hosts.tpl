##
## Ansible Inventory
##
[all]
[all:vars]
ansible_ssh_pass=Pl@tform9
ansible_sudo_pass=Pl@tform9

################################################################################################
## Optional Settings
################################################################################################
manage_network=True
live_migration=True
nested_virt=False
kernel_same_page_merging=False

################################################################################################
## Openstack Groups
################################################################################################
## global variables defined in group_vars/hypervisors.yml
[hypervisors]
hv01 ansible_host=172.16.7.10 ansible_user=centos ha_cluster_ip=172.16.7.10 dhcp=on snat=on
hv02 ansible_host=172.16.7.11 ansible_user=ubuntu ha_cluster_ip=172.16.7.11 dhcp=on snat=on
hv03 ansible_host=172.16.7.12 ansible_user=ubuntu ha_cluster_ip=172.16.7.12 dhcp=on snat=on
hv04 ansible_host=172.16.7.13 ansible_user=ubuntu ha_cluster_ip=172.16.7.13 dhcp=on snat=on

## global variables defined in group_vars/glance.yml
[glance]
hv01 glance_public_endpoint=True

## global variables defined in group_vars/glance.yml
[cinder]
hv02 cinder_ip=172.16.7.11 pvs=["/dev/sdb","/dev/sdc","/dev/sdd","/dev/sde"]

################################################################################################
## Kubernetes Groups
################################################################################################
## global variables defined in group_vars/containervisors.yml
[k8s-master]
cv01 ansible_host=172.16.7.139 ansible_user=centos cluster_uuid=7273706d-afd5-44ea-8fbf-901ceb6bef27

[k8s-worker]
cv02 ansible_host=172.16.7.143 ansible_user=centos cluster_uuid=7273706d-afd5-44ea-8fbf-901ceb6bef27
cv03 ansible_host=172.16.7.194 ansible_user=centos cluster_uuid=7273706d-afd5-44ea-8fbf-901ceb6bef27
