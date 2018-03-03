# Platform9 Autodeplopy
Autodeploy aims to automate the prerequisite tasks required to bring a hypervisor under management by a Platform9 control plane, including package/service prerequisites, host agent(s), and control plane authorization.

## Installation/Setup Instructions

**Step 1 : Define SSH connection details for hypervisors**
* vi inventory/hosts

**Step 2: Run Auto-Deploy**
* ./INSTALL \<target\>

Where '\<target\>' is a hostname or group defined in Ansible inventory file

The first time you run ./INSTALL it will prompt you for various settings related to the Platform9 Control Plane.  If you need to change any settings after the initial run, you can use './INSTALL -s' to re-enter any values.

* Ansible Inventory Example
```
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

## Ansible Inventory Notes

All of your hypervisor nodes should be listed in the Ansible inventory file (inventory/hopsts). They should be listed under the "[hypervisors]" group. Each node should be named after their fully qualified domain name (FQDN) that will be used as the hostname. Here are a few examples for creating Ansible inventory connection details based on common scenarios.

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

## License

Commerical
