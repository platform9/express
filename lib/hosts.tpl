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
hv10 ansible_host=172.16.7.172 ansible_user=centos ha_cluster_ip=172.16.7.172 dhcp=on snat=on
hv11 ansible_host=172.16.7.171 ansible_user=ubuntu ha_cluster_ip=172.16.7.171

## global variables defined in group_vars/glance.yml
[glance]
hv10 glance_public_endpoint=True

################################################################################################
## Kubernetes Groups
################################################################################################
## global variables defined in group_vars/containervisors.yml
[containervisors]
cv01 ansible_host=172.16.7.116 ansible_user=centos cluster_name=c1 cluster_fqdn=c1.platform9.net
cv02 ansible_host=172.16.7.88 ansible_user=centos cluster_name=c1 cluster_fqdn=c1.platform9.net
