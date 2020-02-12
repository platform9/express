#!/bin/bash
####################################################################################################
# Wait for pf9-hostagent to complete convergence
####################################################################################################

basedir=$(dirname $0)
TIMEOUT=900
flag_k8s=0

usage() {
  echo -e "usage: `basename $0` <du_fqdn> <host_id> <du_token>"
  exit 1
}

assert() {
  if [ $# -eq 1 ]; then echo "ASSERT: ${1}"; fi
  exit 1
}

## validate commandline
if [ $# -lt 3 ]; then usage; fi
du_fqdn=${1}
host_id=${2}
token=${3}

# check for flags (optional parameters)
if [ $# -eq 4 -a "${4}" == "k8s" ]; then
  role_filter="python -c 'import sys, json; print json.load(sys.stdin)[\"extensions\"][\"ip_address\"][\"status\"]'"
else
  role_filter="python -c 'import sys, json; print json.load(sys.stdin)[\"role_status\"]'"
fi

####################################################################################################
# Wait for Host Agent to Register
####################################################################################################

echo "[ waiting for pf9-hostagent to complete convergence ]"
echo "--> TIMEOUT = ${TIMEOUT} seconds"
echo "--> flag_k8s=${flag_k8s}"
start_time=`date +%s`
elapsedTime=0
while [ ${elapsedTime} -lt ${TIMEOUT} ]; do
  role_status=$(curl -s -k -H "Content-Type: application/json" -H "X-Auth-Token: ${token}" \
      https://${du_fqdn}/resmgr/v1/hosts/${host_id} | eval "${role_filter}")

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
