#!/bin/bash

basedir=$(dirname $0)
email_list=${basedir}/email_distr.dat

usage () {
  echo "Usage: `basename $0` <openstack-rc> <env>"
  exit 1
}

# validate command line
if [ $# -ne 2 ]; then usage; fi
osrc=${1}
environment=${2}
if [ ! -r ${osrc} ]; then echo "ERROR: failed to open <openstack-rc>"; exit 1; fi

# source <openstack-rc>
source ${osrc}

# validate email distros
if [ ! -r ${email_list} ]; then exit 1; fi

# get day-of-month for today
today=$(date +%d)

# get day-of-month for yesterday
yesterday=$(expr $(date +%d) - 1)

# set target date for metrics analysis
target_date="$(date +%Y-%m)-${yesterday}"

# call pf9-hostpeaks
tmpfile=${basedir}/peak_data/instance-peaks.${environment}.${target_date}.csv
echo "executing: ${basedir}/pf9-hostpeaks.py ${target_date} > ${tmpfile}"
${basedir}/pf9-hostpeaks.py ${target_date} > ${tmpfile}

# send email
for email_addr in `cat ${email_list}`; do
  if [ "${email_addr:0:1}" == "#" -o -z "${email_addr}" ]; then continue; fi
  echo "--> emailing ${email_addr}"
  echo "CSV file attached" | mail -a "${tmpfile}" -r "donotreply@platform9.net" -s "Instance Metrics for ${target_date}" "${email_addr}"
done

