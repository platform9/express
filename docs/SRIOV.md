# Using SR-IOV with Platform9 Express

In PMO version 3.11.x, support for SR-IOV has been introduced. SR-IOV provides increased network performance including higher throughput, lower latency, and lower jitter when compared to virtual switching technologies such as Open vSwitch.

SR-IOV is supported by multiple network interface cards (NICs) provided by many networking vendors, including Intel, Cisco, Mellanox, Broadcom, QLogic, and others.

The following NICs have been tested with the Platform9 PMO 3.11.3 release:

* Mellanox ConnectX-4 Lx EN
* Mellanox ConnectX-5 EN
* Intel X520
* Intel X540-T2
* Broadcom NetXtreme II (BCM57810 / HP 533FLR-T)

The following drivers are considered supported:

* ixgbe
* bnx2x

> Mellanox cards require additional configuration that is outside the scope of this guide and Platform9 Express.

## Limitations

The following are a few of the limitations of SR-IOV:

* Bonded NICs at the host-level are not recommended/not supported for use with SR-IOV. While active/passive bonding may work in this configuration, LACP/802.3ad is definitely not a supported configuration.
* Virtual Functions are automatically assigned to Neutron ports and are not customizable. 
* Instance-level NIC bonding using Virtual Functions is not supported.
* Port security/security groups are not supported.
* VLAN networks are required. Flat (untagged) and overlay networks are not supported.

## System Prerequisites

SR-IOV requires the following:

* BIOS Support (configuration varies by vendor)
* Kernel IOMMU Support
* Kernel IOMMU Passthrough support
* Compatible Network Interface Card (NIC)

> When SR-IOV capable NICs are used in conjunction with Open vSwitch bridges, you have the option of using an existing provider label, such as **external**, or using a dedicated provider. When sharing a provider network between SR-IOV and non-SR-IOV ports, communication between the ports on the same network is permitted. Using a dedicated provider will require you to call out a second bridge mapping, such as `sriov:br-sriov`, to allow DHCP ports connected to a vSwitch to communicate with the SR-IOV ports.

### Kernel IOMMU Support

Using **dmesg**, you can verify if IOMMU is enabled with the following command:

```
# dmesg | grep IOMMU
```

If you do not see the message ```DMAR: IOMMU enabled```, then proceed with the following steps:

First, enable IOMMU support in the kernel by modifying the GRUB configuration at **/etc/default/grub**:

```
GRUB_CMDLINE_LINUX="... intel_iommu=on" #Intel-based Systems

GRUB_CMDLINE_LINUX="... amd_iommu=on" #AMD-based Systems
```

Next, update GRUB:

```
update-grub
```

> Once the kernel configuration has been modified, you must reboot for the changes to take effect.

### IOMMU Passthrough Support

To enable IOMMU passthrough support in the kernel, please complete the following steps:

First, enable passthrough support in the kernel by modifying the GRUB configuration at **/etc/default/grub**:

```
GRUB_CMDLINE_LINUX="... iommu=pt"
```

Then, update GRUB:

```
update-grub
```

> Once the kernel configuration has been modified, you must reboot for the changes to take effect.

## Deploying PMO with SR-IOV support using Express

Using the Platform9 Express tool, operators can deploy PMO with support for SR-IOV. The Express tool will perform many of the tasks outlined in the previous sections, including enabling IOMMU and passthrough support in the kernel, as well as implementing a unit file for persisting VFs across reboots.

> Given the complexity involved in supporting Mellanox NICs, the Express tool will initially only support Intel NICs using the ixgbe driver. This includes the Intel X520, X540, and X550 families.

The necessary configuration details can be implemented globally using **group_vars**, or on an individual host basis using **host_vars**. Each method is described below.

### Host Variables

Compute node-specific configurations can be implemented using what is known as host_vars. Configurations that may vary between hosts include:

* Network interface name
* Quantity of network interfaces used for SRIOV
* Provider network mappings
* Number of VFs per interface
 
Using **host_vars**, the following are some variables that can be modified:

* physical_device_mappings (required)
* sriov_numvfs (required)
* neutron_ovs_bridge_mappings (optional)

In this example, two hosts have different NICs installed that report different names to the operating system.

```
root@compute01:~# ip link show
...
6: ens1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq portid 0002c90300ffe511 state UP mode DEFAULT group default qlen 1000
    link/ether 00:02:c9:ff:e5:10 brd ff:ff:ff:ff:ff:ff
7: ens1d1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq portid 0002c90300ffe512 state UP mode DEFAULT group default qlen 1000
    link/ether 00:02:c9:ff:e5:11 brd ff:ff:ff:ff:ff:ff
```

```
root@compute02:~# ip link show
...
3: ens1f0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000
    link/ether 90:e2:ba:a2:1b:88 brd ff:ff:ff:ff:ff:ff
5: ens1f1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000
    link/ether 90:e2:ba:a2:1b:89 brd ff:ff:ff:ff:ff:ff
```

NIC naming can vary based on the kernel version, NIC driver, and the PCI slot where the card is installed. In this example, the NIC installed in each host is from a different manufacturer and uses a different driver:

```
root@compute01:~# ethtool -i ens1
driver: mlx4_en
version: 4.0-0
firmware-version: 2.42.5000
expansion-rom-version:
bus-info: 0000:08:00.0
supports-statistics: yes
supports-test: yes
supports-eeprom-access: no
supports-register-dump: no
supports-priv-flags: yes
```

```
root@compute02:~# ethtool -i ens1f0
driver: ixgbe
version: 5.1.0-k
firmware-version: 0x61bd0001
expansion-rom-version:
bus-info: 0000:08:00.0
supports-statistics: yes
supports-test: yes
supports-eeprom-access: yes
supports-register-dump: yes
supports-priv-flags: yes
```

The **host_vars** for each host can be implemented in a file that corresponds to the host's short name located at **/opt/pf9-express/host_vars/<shortname>.yml**. In the following example, **compute01** uses a single network interface for SR-IOV, while **compute02** uses two. SR-IOV networks will leverage a new provider label named **sriov** and 8 VFs per interface, as shown here:

```
---
# compute01.yml
physical_device_mappings:
  - sriov:ens1
sriov_numvfs:
  - ens1:8
```

```
---
# compute02.yml
physical_device_mappings:
  - sriov:ens1f0
  - sriov:ens1f1
sriov_numvfs:
  - ens1f0:8
  - ens1f1:8
```

> SR-IOV supports VLAN networks only. Flat and overlay networks are not supported.

### Group Variables

Group-wide configurations can be implemented using what is known as **group_vars**. Configurations that may be consistent between groups include:

* Network interface name
* Number of VFs per interface
* Provider network mappings

Using **group_vars**, the following are some variables that can be modified:

* neutron_ovs_bridge_mappings
* sriov_numvfs
* physical_device_mappings

The **group_vars** for the **hypervisors** group can be implemented in a file that corresponds to the group's name located at **/opt/pf9-express/group_vars/<groupname>.yml**. In the following example, every host in the **hypervisors** group has the same NIC installed in the same slot, so the naming convention is consistent across all hosts. A second provider bridge mapping has been established that will allow non-SR-IOV capable ports, such as DHCP, to connect to a vSwitch and communicate with SR-IOV ports:

```
---
# hypervisors.yml
...
neutron_ovs_bridge_mappings: "external:br-pf9, sriov:br-sriov"
physical_device_mappings:
  - sriov:ens1f0
  - sriov:ens1f1
sriov_numvfs:
  - ens1f0:8
  - ens1f1:8
...
```

> Host vars take precedence over group vars. If a small number of hosts vary from the greater group, feel free to implement the respective **host_vars** files accordingly.

### Inventory File

To enable support for SR-IOV on a host, the inventory must be modified according so that SR-IOV related tasks are executed. One method of enabling support for a host is to add the **sriov=on** variable to an individual host in the **hypervisors** group, as shown here:

```
[hypervisors]
compute01 ansible_host=10.50.0.197 vm_console_ip=10.50.0.197 ha_cluster_ip=10.50.0.197 tunnel_ip=10.50.0.197 dhcp=on snat=on sriov=on
compute02 ansible_host=10.50.0.196 vm_console_ip=10.50.0.196 tunnel_ip=10.50.0.196 dhcp=on snat=on sriov=on
```

SR-IOV can be enabled group-wide by modifying the respective **group_vars** file, as shown here:

```
---
# hypervisors.yml
...
####################
# SRIOV
####################
sriov: "on"
...
```

Lastly, SR-IOV can be enabled via the respective **host_vars** file, as shown here:

```
---
# compute01.yml 
sriov: "on"
physical_device_mappings:
  - sriov:ens1
```

### Installation
Once the respective configuration is in place, install PMO with Express using some variation of the following:

```
# ./pf9-express -a pmo
```

To refresh VFs, run **pf9-express** with the **refresh-sriov** tag:

```
# ./pf9-express -t refresh-sriov hypervisors
```
