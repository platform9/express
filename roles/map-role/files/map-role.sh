#!/bin/bash
####################################################################################################
# Install Platform9 On-Prem Kubernetes for Bare-Metal
####################################################################################################

basedir=$(dirname $0)
platform=""
flag_attachCluster=0
config_file=${basedir}/isv.conf

# set defaults
cluster_name="defaultCluster"

usage() {
  echo -e "usage: `basename $0` <ctrl_ip> <role> <role_metadata> <host_id> <admin_user> <admin_password> [args]\n"
  echo "-k               : download/install/configure Kubectl from management server"
  echo "-a               : attach node to cluster"
  echo
  exit 1
}

assert() {
  if [ $# -eq 1 ]; then echo "ASSERT: ${1}"; fi
  exit 1
}

validate_platform() {
  # check if running CentOS 7.4
  if [ -r /etc/centos-release ]; then
    release=$(cat /etc/centos-release | cut -d ' ' -f 4)
    if [[ ! "${release}" == 7.4.* ]]; then assert "unsupported CentOS release: ${release}"; fi
    platform="centos"
    host_os_info=$(cat /etc/centos-release)
  elif [ -r /etc/lsb-release ]; then
    release=$(cat /etc/lsb-release | grep ^DISTRIB_RELEASE= /etc/lsb-release | cut -d '=' -f2)
    if [[ ! "${release}" == 16.04* ]]; then assert "unsupported CentOS release: ${release}"; fi
    platform="ubuntu"
    ubuntu_release=$(cat /etc/lsb-release | grep ^DISTRIB_RELEASE | cut -d = -f2)
    host_os_info="${platform} ${ubuntu_release}"
  else
    assert "unsupported platform"
  fi
}

banner() {
  if [ $# -ge 1 ]; then title=${1}; fi
  if [ $# -eq 2 -a "${2}" == "-n" ]; then echo; fi
  echo "********************************************************************************"
  echo "*** ${title}"
  echo "********************************************************************************"
}

wait_n() {
  time_to_wait=10
  if [ $# -eq 1 ]; then time_to_wait=${1}; fi

  local cnt=0
  while [ ${cnt} -lt ${time_to_wait} ]; do
    echo -n "."
    sleep 1
    ((cnt++))
  done
  echo
}

attach_node() {
  export LD_LIBRARY_PATH="/opt/pf9/python/pf9-lib:/opt/pf9/python/pf9-hostagent-lib:${LD_LIBRARY_PATH}"
  export PYTHONPATH="/opt/pf9/python/lib/python2.7:${PYTHONPATH}"
  if [ ! -r /opt/pf9/setupd/bin/attach-node ]; then assert "attach-node not found"; fi
  /opt/pf9/setupd/bin/attach-node --mgmt-ip ${ctrl_ip} --admin-user ${admin_user} --admin-password ${admin_password} \
      --hostid ${host_id} --cluster-name ${cluster_name}
  if [ $? -ne 0 ]; then return 1; fi
}

create_cluster() {
  export LD_LIBRARY_PATH="/opt/pf9/python/pf9-lib:/opt/pf9/python/pf9-hostagent-lib:${LD_LIBRARY_PATH}"
  export PYTHONPATH="/opt/pf9/python/lib/python2.7:${PYTHONPATH}"
  banner "Creating Cluster : ${cluster_name} | ${cluster_fqdn}" -n
  /opt/pf9/setupd/bin/add-cluster --ctrl-ip ${ctrl_ip} --admin-user ${admin_user} --admin-password ${admin_password} \
      --cluster-fqdn ${cluster_fqdn} --cluster-name ${cluster_name}
  if [ $? -ne 0 ]; then exit 1; fi
}

## validate commandline
if [ $# -lt 6 ]; then usage; fi
ctrl_ip=${1}
role=${2}
role_metadata=${3}
host_id=${4}
admin_user=${5}
admin_password=${6}

## process optional arguments
shift 6
while [ $# -gt 0 ]; do
  case ${1} in
  --clusterName)
    if [ $# -lt 2 ]; then usage; fi
    cluster_name=${2}
    shift 2
    ;;
  --clusterFqdn)
    if [ $# -lt 2 ]; then usage; fi
    cluster_fqdn=${2}
    shift 2
    ;;
  *)
    usage
    ;;
  esac
done

## log parameters
echo "[Input Parameters]"
echo "--> ctrl_ip = ${ctrl_ip}"
echo "--> role = ${role}"
echo "--> role_metadata = ${role_metadata}"
echo "--> host_id = ${host_id}"
echo "--> admin_user = ${admin_user}"
echo "--> admin_password = ${admin_password}"
echo "--> cluster_name = ${cluster_name}"
echo "--> cluster_fqdn = ${cluster_fqdn}"

## validate role
case ${role} in
pf9-kube|pf9-ostackhost|pf9-ostackhost-neutron|pf9-glance-role|pf9-celiometer-role|pf9-neutron-ovs-agent|pf9-neutron-metadata-agent|pf9-neutron-l3-agent|pf9-neutron-dhcp-agent|pf9-neutron-base)
  ;;
*)
  assert "invalid role: ${role}"
esac

## validate logged in as root
uid=$(id -u)
if [ ${uid} -ne 0 ]; then assert "this operation must be run as root"; fi

## set auth url
auth_url=https://${ctrl_ip}/keystone/v3

## validate platform (CentOS 7.4 or Ubuntu 16.04)
validate_platform

####################################################################################################
## Attach to Cluster
####################################################################################################
if [ ${flag_attachCluster} -eq 1 ]; then
  attach_node
  exit 0
fi

####################################################################################################
# Get Keystone Token
####################################################################################################
banner "Getting Keystone Token" -n
token=`curl -k -i -H "Content-Type: application/json" ${auth_url}/auth/tokens?nocatalog \
    -d "{ \"auth\": { \"identity\": { \"methods\": [\"password\"], \"password\": { \"user\": { \"name\": \"${admin_user}\", \"domain\": {\"id\": \"default\"}, \"password\": \"${admin_password}\" } } }, \"scope\": { \"project\": { \"name\": \"service\", \"domain\": {\"id\": \"default\"}}}}}" 2>/dev/null | grep -i ^X-Subject-Token | awk -F : '{print $2}' | sed -e 's/ //g' | sed -e 's/\r//g'`

####################################################################################################
# Wait for Host Agent to Register
####################################################################################################
banner "Waiting for Host Agent to Register" -n
wait_n 45
curl -k -i -H "Content-Type: application/json" -H "X-Auth-Token: ${token}" https://${ctrl_ip}/resmgr/v1/hosts/${host_id}; echo
if [ $? -ne 0 ]; then exit 1; fi

####################################################################################################
# Display ROle Metadata
####################################################################################################
echo "--- ROLE METADATA --------------------------------------------------------------"
cat ${role_metadata} | python -m json.tool
echo "--------------------------------------------------------------------------------"

####################################################################################################
# Assign Kubernetes Roles
####################################################################################################
if [ "${role}" == "pf9-kube" ]; then
  banner "Assigning Role : ${role}" -n
  curl -v -k -i -X PUT -H "Content-Type: application/json" -H "X-Auth-Token: ${token}" \
      -d "@{role_metadata}" https://${ctrl_ip}/resmgr/v1/hosts/${host_id}/roles/${role} > /dev/null 2>&1

  # create cluster (if not exist)
  curl -k -H "Content-Type: application/json" -H "X-Auth-Token: ${token}" \
        https://${ctrl_ip}/qbert/v1/clusters/${object_id} | python -m json.tool | grep name | grep "${cluster_name}" > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    echo "cluster validated (cluster '${cluster_name}' already exists)"
  else
    echo "INFO: cluster does not exists - creating"
    cluster_fqdn="c2.ilabs.net"
    create_cluster
  fi

  # attach node to cluster
  # NOTE: If k8s containers fail to start, run: 'systemctl restart pf9-kubelet.service'
  banner "Attaching Node to Cluster" -n
  wait_n 60
  attach_node
fi

####################################################################################################
# Assign Openstack Roles
####################################################################################################
if [ "${role}" != "pf9-kube" ]; then
  banner "Assigning Role : ${role}" -n
  curl -v -k -i -X PUT -H "Content-Type: application/json" -H "X-Auth-Token: ${token}" \
       -d "@${role_metadata}" https://${ctrl_ip}/resmgr/v1/hosts/${host_id}/roles/${role}
  if [ $? -ne 0 ]; then exit 1; fi
fi

echo -e "\n[ COMPLETE ]\n"
exit 0
