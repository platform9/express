################################################################################################
## Ansible Inventory
################################################################################################
[all]
[all:vars]
ansible_ssh_pass=Pl@tform9
ansible_sudo_pass=Pl@tform9

################################################################################################
## Optional Settings
################################################################################################
manage_network=True
live_migration=True
nested_virt=True
kernel_same_page_merging=False

################################################################################################
## Openstack Groups
################################################################################################
## global variables defined in group_vars/hypervisors.yml
[hypervisors]
{{NODE01}} ansible_host={{NODE01_MGT_IP}} ansible_user=centos cluster_ip={{NODE01_CLUSTER_IP}} dhcp=on snat=on
{{NODE02}} ansible_host={{NODE02_MGT_IP}} ansible_user=centos cluster_ip={{NODE02_CLUSTER_IP}} dhcp=on snat=on
{{NODE02}} ansible_host={{NODE03_MGT_IP}} ansible_user=centos cluster_ip={{NODE03_CLUSTER_IP}}
{{NODE02}} ansible_host={{NODE04_MGT_IP}} ansible_user=centos cluster_ip={{NODE04_CLUSTER_IP}}

## global variables defined in group_vars/glance.yml
[glance]
{{NODE01}} glance_public_endpoint=True
{{NODE02}} glance_public_endpoint=False

## global variables defined in group_vars/glance.yml
[cinder]
{{NODE03}} cinder_ip={{NODE03_CINDER_IP}} pvs=["/dev/sdb","/dev/sdc"]
{{NODE04}} cinder_ip={{NODE04_CINDER_IP}} pvs=["/dev/sdb","/dev/sdc"]

## global variables defined in group_vars/live-migration.yml
[live-migration]

## network configuration for bond0 (implemented by network-hook if defined)
[ovsconfig]
{{NODE01}} bond_members='["ens192"]' bond_sub_interfaces='[{"vlanid":"243","ip":"172.16.243.11","mask":"255.255.255.0"}]'
{{NODE02}} bond_members='["ens192"]' bond_sub_interfaces='[{"vlanid":"243","ip":"172.16.243.12","mask":"255.255.255.0"}]'
{{NODE03}} bond_members='["ens192"]' bond_sub_interfaces='[{"vlanid":"243","ip":"172.16.243.13","mask":"255.255.255.0"}]'
{{NODE04}} bond_members='["ens192"]' bond_sub_interfaces='[{"vlanid":"243","ip":"172.16.243.14","mask":"255.255.255.0"}]'
