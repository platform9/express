# Platform9 Autodeplopy
Autodeploy aims to automate the prerequisite tasks required to bring a hypervisor under management by a Platform9 control plane, including package/service prerequisites, host agent(s), and platform authorization.

## Installation/Setup Instructions

## Step 1 : clone the repository
* git clone https://github.com/platform9/autodeploy.git

## Step 2 : install Ansible on control host (the host that will execute autodeploy)
* sudo yum -y install epel-release
* sudo yum -y install ansible

## Step 3: configure SSH access to localhost
* make sure you can SSH to localhost as the user you're logged in as (by configuring SSH keys and configuring ~/.ss/authorized_keys)
* configure 'ansible_user' vasriable in the [a;;"vars] section of autodeploy/inventory/hosts
* validate by running 'ansible -m setup localhost'

## Step 4: install prerequisites
* cd autodeploy
* ansible-playbook -l localhost prereqs-controlhost.yml

## Step 5 : configure environment
Define site-specific variables in group_vars/all.yml
* vi group_vars/all.yml

## Step 6 : define SSH connection details for hypervisors (Nova) and/or image (Glance) nodes in Ansible inventory file
* vi inventory/hosts

## Running Autodeploy

Execute autodeploy playbook
* ansible-playbook pf9-autodeploy.yml

## Usage Notes

**1. Hypervisor-related variables**

* group_vars/all.yml
    * os_region = OpenStack region.
    * os_username = OpenStack admin username.
    * os_password: OpenStack password.
    * os_tenant: OpenStack admin project.
    * du_url = The unique URL provided by Platform9 to access the controller resources.

Image node required variable:

* group_vars/all.yml
    * pf9_id

## Optional variables:

* group_vars/all.yml
    * manage_hostname = Boolean value. Set the hostname equal to the Ansible inventory_hostname for the host.
    * manage_resolvers = Boolean value. Append servers listed in the "dns_resolvers" variable to the resolvers file.
    * dns_resolvers = The DNS resolvers to use for the remote node.


## Inventory

All of the hypervisor nodes should be listed in the inventory file. They should be under the "hypervisors" group. Each node should be named after their fully qualified domain name (FQDN) that will be used as the hostname. Here are a few examples for creating Ansible inventory connection details based on common scenarios.

* SSH directly in as root.
```
<FQDN> ansible_host=<IP> ansible_port=<SSH_PORT> ansible_user=root
```

* SSH in as a privileged user and run Ansible tasks using "sudo."
```
<FQDN> ansible_host=<IP> ansible_port=<SSH_PORT> ansible_become=True ansible_user=<SSH_USER> ansible_become_method=sudo
```

* SSH in as a privileged user and then switch to the root user with "su" to run Ansible tasks.
```
<FQDN> ansible_host=<IP> ansible_port=<SSH_PORT> ansible_become=True ansible_user=<SSH_USER> ansible_become_method=su ansible_user=<SSH_USER>
```

* Hypervisor and image storage group inventory example:
```
# vim production
compute01.domain.tld ansible_host=10.0.0.11 ansible_port=2222 ansibler_user=root
compute02.domain.tld ansible_host=10.0.0.12 ansible_become=True ansible_user=bob ansible_become_method=sudo
compute03.domain.tld ansible_host=10.0.0.13 ansible_port=2222 ansible_become=True ansible_user=joe ansible_become_method=su
image01.domain.tld ansible_host=10.0.0.71
image02.domain.tld ansible_host=10.0.0.72

[hypervisors]
compute[01:03].domain.tld

[image_storage]
image[01:02].domain.tld
```

## License

Commerical
