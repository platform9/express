#!/bin/bash

ifcfg_base=/etc/sysconfig/network-scripts

usage() {
  echo "Usage: `basename $0` <phy_ifName> <ovs_bridgeName>"
  exit 1
}

assert() {
  if [ $# -eq 1 ]; then echo "ASSERT: ${1}"; fi
  exit 1
}

# validate command line
if [ $# -ne 2 ]; then usage; fi
phy_ifName=${1}
ovs_bridgeName=${2}

# define paths to ifcfg-*
phy_ifcfg="${ifcfg_base}/ifcfg-${phy_ifName}"
br_ifcfg="${ifcfg_base}/ifcfg-${ovs_bridgeName}"

# validate phy_ifName
if [ ! -r ${phy_ifcfg} ]; then assert "invalid physical interface (phy_ifName)"; fi

# validate ovs_bridgeName
ovs-vsctl show | grep "Interface \"br-pf9\"" > /dev/null 2>&1
if [ $? -ne 0 ]; then assert "invalid bridge interface (ovs_bridgeName)"; fi

# copy phy_ifName
if [ ! -r ${br_ifcfg} ]; then /bin/cp -f ${phy_ifcfg} ${br_ifcfg}; fi

# validate br_ifcfg
if [ ! -r ${br_ifcfg} ]; then assert "failed to create config file for ovs_bridgeName"; fi

# update phy_ifcfg
tokens="DEFROUTE IPADDR NETMASK GATEWAY"
for token in ${tokens}; do
  sed -i "/^${token}/ d" ${phy_ifcfg}
done

# update br_ifcfg
tokens="HWADDR DEVICE"
for token in ${tokens}; do
  sed -i "/^${token}/ d" ${br_ifcfg}
done
echo "DEVICE=${ovs_bridgeName}" >> ${br_ifcfg}

# restart networking
(nohup ovs-vsctl add-port br-pf9 ${phy_ifName} && systemctl restart network) &

exit 0
