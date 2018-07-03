##
## Ansible Inventory
##
[all]
[all:vars]
ansible_ssh_pass=Pl@tform9
ansible_sudo_pass=Pl@tform9
pf9_uid=1001
pf9_gid=1001

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
hv10 ansible_host=172.16.7.172 ansible_user=centos ha_cluster_ip=172.16.7.172 dhcp=on snat=on
hv11 ansible_host=172.16.7.171 ansible_user=ubuntu ha_cluster_ip=172.16.7.171

## global variables defined in group_vars/glance.yml
[glance]
hv10 glance_public_endpoint=True

## global variables defined in group_vars/glance.yml
[cinder]
hv11 cinder_ip=10.31.254.252 pvs=["/dev/sdb","/dev/sdc","/dev/sdd","/dev/sde"]

################################################################################################
## Kubernetes Groups
################################################################################################
## global variables defined in group_vars/containervisors.yml
[k8s-master]
cv01 ansible_host=172.16.7.139 ansible_user=centos cluster_uuid=7273706d-afd5-44ea-8fbf-901ceb6bef27

[k8s-worker]
cv02 ansible_host=172.16.7.143 ansible_user=centos cluster_uuid=7273706d-afd5-44ea-8fbf-901ceb6bef27
cv03 ansible_host=172.16.7.194 ansible_user=centos cluster_uuid=7273706d-afd5-44ea-8fbf-901ceb6bef27
