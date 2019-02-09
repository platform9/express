#!/bin/bash
####################################################################################################
# Wait for pf9-hostagent to complete convergence
####################################################################################################

basedir=$(dirname $0)
TIMEOUT=900
flag_k8s=0

usage() {
  echo -e "usage: `basename $0` <ctrl_ip> <host_id> <admin_user> <admin_password>"
  exit 1
}

assert() {
  if [ $# -eq 1 ]; then echo "ASSERT: ${1}"; fi
  exit 1
}

## validate commandline
if [ $# -lt 4 ]; then usage; fi
ctrl_ip=${1}
host_id=${2}
admin_user=${3}
admin_password=${4}

# check for flags (optional parameters)
if [ $# -eq 5 -a "${5}" == "k8s" ]; then
  flag_k8s=1
  sleep 120
  exit 0
fi

## set auth url
auth_url=https://${ctrl_ip}/keystone/v3

####################################################################################################
# Get Keystone Token
####################################################################################################
token=`curl -k -i -H "Content-Type: application/json" ${auth_url}/auth/tokens?nocatalog \
    -d "{ \"auth\": { \"identity\": { \"methods\": [\"password\"], \"password\": { \"user\": { \"name\": \"${admin_user}\", \"domain\": {\"id\": \"default\"}, \"password\": \"${admin_password}\" } } }, \"scope\": { \"project\": { \"name\": \"service\", \"domain\": {\"id\": \"default\"}}}}}" 2>/dev/null | grep -i ^X-Subject-Token | awk -F : '{print $2}' | sed -e 's/ //g' | sed -e 's/\r//g'`

####################################################################################################
# Wait for Host Agent to Register
####################################################################################################

echo "[ waiting for pf9-hostagent to complete convergence ]"
echo "--> TIMEOUT = ${TIMEOUT} seconds"
echo "--> flag_k8s=${flag_k8s}"
start_time=`date +%s`
elapsedTime=0
while [ ${elapsedTime} -lt ${TIMEOUT} ]; do
  role_status=$(curl -k -H "Content-Type: application/json" -H "X-Auth-Token: ${token}" \
      https://${ctrl_ip}/resmgr/v1/hosts/${host_id} 2>/dev/null | python -m json.tool | grep role_status)
  if [ -n "${role_status}" ]; then
    role_status=$(echo ${role_status} | cut -d : -f2 | sed -e 's/\"//g' | sed -e 's/,//g' | sed -e 's/ //g')
  fi

  if [ "${role_status}" == "ok" ]; then break; fi

  # update elapsed time
  current_t=`date +%s`; elapsedTime=$((current_t - start_time))
  sleep 5
done

# display timeout message
if [ ${elapsedTime} -ge ${TIMEOUT} ]; then
  assert "*** TIMEOUT EXCEEDED ***"
fi

echo "convergence complete"
exit 0
