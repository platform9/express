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
tmpfile=${basedir}/peak_data/instance-metrics.${environment}.${target_date}.csv
echo "$(date -u) >>> [${environment}] pf9-hostpeaks.py ${target_date}"
${basedir}/pf9-hostpeaks.py ${target_date} > ${tmpfile}

# configure email
email_from=dan.wright@platform9.com
email_subj="${environment} : Instance Metrics ${target_date}"
email_body="CSV file attached"
email_attachment=${tmpfile}

# send email
for email_addr in `cat ${email_list}`; do
  if [ "${email_addr:0:1}" == "#" -o -z "${email_addr}" ]; then continue; fi

  email_to="${email_addr}"
  echo "$(date -u) >>> mail -a $(basename ${email_attachment}) ${email_to}"
  echo "${email_body}" | mail -a ${email_attachment} -r ${email_from} -s "${email_subj}" ${email_to}
done
echo "$(date -u) >>> complete"

exit 0
