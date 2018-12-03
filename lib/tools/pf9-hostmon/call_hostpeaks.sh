#!/bin/bash

basedir=$(dirname $0)
email_list=${basedir}/email_distr.dat
target_date=""

usage () {
  echo "Usage: `basename $0` <openstack-rc> <env> [<yyyy-mm-dd>]"
  exit 1
}

# validate command line
if [ $# -lt 2 ]; then usage; fi
osrc=${1}
environment=${2}
if [ ! -r ${osrc} ]; then echo "ERROR: failed to open <openstack-rc>"; exit 1; fi

# process optional args
if [ $# -eq 3 ]; then
  target_date=${3}
else
  target_date=$(date -d "1 day ago" '+%Y-%m-%d')
fi

# source <openstack-rc>
source ${osrc}

# validate email distros
if [ ! -r ${email_list} ]; then exit 1; fi

# call pf9-hostpeaks
echo "$(date -u) >>> [${environment}] pf9-hostpeaks.py ${target_date} ${environment}"
${basedir}/pf9-hostpeaks.py ${target_date} ${environment}

# sort csv file
peak_report=${basedir}/du_peakdata/${environment}/${target_date}/instance-metrics.${environment}.${target_date}.csv
peak_report_sorted=/tmp/instance-metrics.${environment}.${target_date}.csv
$(sort ${peak_report} -r -t , -k2 > ${peak_report_sorted})

# configure email
graph_link=$(cat ${basedir}/du_metrics/${environment}/${target_date}/link_to_graph_cpu.dat)
email_from=dan.wright@platform9.com
email_subj="${environment} : Instance Metrics ${target_date}"
email_body="--- CSV file attached ---"
email_attachment1=${peak_report_sorted}

# send email
for email_addr in `cat ${email_list}`; do
  if [ "${email_addr:0:1}" == "#" -o -z "${email_addr}" ]; then continue; fi
  echo "$(date -u) >>> mail -a $(basename ${email_attachment1}) ${email_addr}"

  # build mail contents
  tmpfile=/tmp/mail.$$.tmp
  echo "To: ${email_addr}" > ${tmpfile}
  echo -e "\n[Region CPU Trend : Instances]\n${graph_link}" >> ${tmpfile}
  echo -e "\n[Region CPU Peaks : Instances]\n${email_body}" >> ${tmpfile}

  mail -a ${email_attachment1} -s "${email_subj}" ${email_addr} < ${tmpfile}
done
echo "$(date -u) >>> complete"

rm -f ${peak_report_sorted}
rm -f ${tmpfile}

exit 0
