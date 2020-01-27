#!/bin/bash

update_openstack_rc() {
  if [ $# -ne 5 ]; then return 1; fi

  if [ -r ${oscli_rc_file} ]; then rm -f ${oscli_rc_file}; touch ${oscli_rc_file}; fi

  echo "export OS_AUTH_URL=https://${1}/keystone/v3" >> ${oscli_rc_file}
  echo "export OS_IDENTITY_API_VERSION=3" >> ${oscli_rc_file}
  echo "export OS_REGION_NAME='${2}'" >> ${oscli_rc_file}
  echo "export OS_USERNAME='${4}'" >> ${oscli_rc_file}
  echo "export OS_PASSWORD='${5}'" >> ${oscli_rc_file}
  echo "export OS_PROJECT_NAME='${3}'" >> ${oscli_rc_file}
  echo "export OS_PROJECT_DOMAIN_ID=${OS_PROJECT_DOMAIN_ID:-'default'}" >> ${oscli_rc_file}
}

update_template() {
  if [ $# -ne 2 ]; then return 1; fi

  # init buffer
  buffer=/tmp/cm-buffer.$$.tpl
  rm -f ${buffer} && touch ${buffer}
  if [ ! -r ${buffer} ]; then
    echo "failed to initialize buffer ${buffer}"
    exit 1
  fi

  local target_key=${1}
  local target_val=${2}
  if [ -r ${pf9_config} ]; then
    while read -r line; do
      # skip comments and blank lines
      if [ "${line:0:1}" == "#" -o -z "${line}" ]; then
        echo "${line}" >> $buffer
        continue
      fi

      key=`echo ${line} | cut -d \| -f1`
      val=`echo ${line} | cut -d \| -f2`
      if [ "${key}" == "${target_key}" ]; then
        echo "${key}|${target_val}" >> $buffer
      else
        echo "${line}" >> $buffer
      fi
    done < ${pf9_config}

    # replace pf9_config with buffer
    cp -f ${buffer} ${pf9_config}
    if [ $? -ne 0 ]; then
      echo "ERROR: failed to replace pf9_config with buffer"
      exit 1
    fi
  fi
}

get_input() {
  if [ $# -ne 5 ]; then return 1; fi

  local arg_name=${1}
  local arg_desc=${2}
  local arg_default=${3}
  local arg_allowed_values=${4}
  local arg_type=${5}

  local input_isValid=0
  local prompt_string

  # create array of allowed values
  local IFS=","
  allowed_values=(${arg_allowed_values})

  # display prompt to user
  while [ ${input_isValid} -eq 0 ]; do
    # define prompt
    if [ "${arg_default}" == "-" ]; then
      prompt_str="${2}: "
    else
      prompt_str="${2} [${arg_default}]: "
    fi

    # get input from user
    echo -n ${prompt_str}
    read -r reply

    # if empty reply from user, substitute default (if defined)
    if [ -z "${reply}" -a "${arg_default}" != "null-disallowed" ]; then reply=${arg_default}; fi

    # validate reply
    if [ -z "${reply}" -a "${arg_default}" == "null-allowed" ]; then
      echo "--> accepted: ${reply}"
      input_isValid=1
    elif [ -z "${reply}" -a "${arg_default}" == "null-disallowed" ]; then
      echo "--> null response not allowed"
    elif [ ! -z "${reply}" -a "${arg_allowed_values}" != "-" ]; then
      in_array "${reply}" "${allowed_values[@]}"
      if [ $? -eq 0 ]; then
        echo "--> accepted: ${reply}"
        input_isValid=1
      else
        echo "ERROR: allowed values = [${arg_allowed_values}]"
      fi
    else
      echo "--> accepted: ${reply}"
      input_isValid=1
    fi

    # paramterize user response into template
    update_template "${arg_name}" "${reply}"
    if [ $? -ne 0 ]; then echo "ERROR: failed to update template, aborting."; exit 1; fi
  done
}

prompt_user() {
  local arg_name="-"
  local arg_desc="-"
  local arg_default="-"
  local arg_allowed_values="-"
  local arg_type="-"

  local IFS="|"
  config_args=(${1})
  case ${#config_args[@]} in
  1) arg_name=${config_args[0]}
     ;;
  2) arg_name=${config_args[0]}
     arg_desc=${config_args[1]}
     ;;
  3) arg_name=${config_args[0]}
     arg_desc=${config_args[1]}
     arg_default=${config_args[2]}
     ;;
  4) arg_name=${config_args[0]}
     arg_desc=${config_args[1]}
     arg_default=${config_args[2]}
     arg_allowed_values=${config_args[3]}
     ;;
  5) arg_name=${config_args[0]}
     arg_desc=${config_args[1]}
     arg_default=${config_args[2]}
     arg_allowed_values=${config_args[3]}
     arg_type=${config_args[4]}
     ;;
  esac

  get_input "${arg_name}" "${arg_desc}" "${arg_default}" "${arg_allowed_values}" "${arg_type}"
}

run_setup() {
  v1=$(grep ^du_url ${pf9_config} | cut -d \| -f2)
  v2=$(grep ^os_username ${pf9_config} | cut -d \| -f2)
  v3=$(grep ^os_password ${pf9_config} | cut -d \| -f2)
  v4=$(grep ^os_region ${pf9_config} | cut -d \| -f2)
  v5=$(grep ^os_tenant ${pf9_config} | cut -d \| -f2)
  v6=$(grep ^manage_hostname ${pf9_config} | cut -d \| -f2)
  v7=$(grep ^manage_resolver ${pf9_config} | cut -d \| -f2)
  v8=$(grep ^dns_resolver1 ${pf9_config} | cut -d \| -f2)
  v9=$(grep ^dns_resolver2 ${pf9_config} | cut -d \| -f2)
  v10=$(grep ^proxy_url ${pf9_config} | cut -d \| -f2)

  pf9_nv_pairs=(
    "du_url|PF9 Management Plane URL|${v1}"
    "os_username|Admin Username|${v2}"
    "os_password|Admin Password|${v3}"
    "os_region|Region|${v4}"
    "os_tenant|Tenant|${v5}"
    "manage_hostname|Manage Hostname [true,false]|${v6}|true,false"
    "manage_resolver|Manage DNS Resolver [true,false]|${v7}|true,false"
    "dns_resolver1|DNS Resolver 1|${v8}"
    "dns_resolver2|DNS Resolver 2|${v9}"
    "proxy_url|Proxy URL|${v10}"
  )

  echo "NOTE: to enter a NULL value for prompt, enter '-'"
  for config_nv in "${pf9_nv_pairs[@]}"; do
    echo
    prompt_user "${config_nv}"
  done; echo

  build_config
}

init_config() {
  cp -f ${pf9_config_tpl} ${pf9_config}
  if [ $? -ne 0 ]; then assert "failed to initialize config file"; fi
}

build_config() {
  # copy template for inventory/hosts
  if [ $# -eq 1 -a "${1}" == "--skip-inventory-check" ]; then
    :
  else
    if [ -r ${basedir}/inventory/hosts ]; then
      getYN "Ansible inventory file exists - overwrite with template? "
      if [ $? -eq 0 ]; then /bin/cp -f ${basedir}/lib/hosts.tpl ${basedir}/inventory/hosts; fi
      echo
    else
      /bin/cp -f ${basedir}/lib/hosts.tpl ${basedir}/inventory/hosts
    fi
  fi

  rm -f ${pf9_group_vars} && touch ${pf9_group_vars}
  if [ $? -ne 0 ]; then assert "failed to initialize group vars: ${pf9_group_vars}"; fi
  
  # read current config values
  local du_url=$(grep ^du_url ${pf9_config} | cut -d \| -f2)
  local os_username=$(grep ^os_username ${pf9_config} | cut -d \| -f2)
  local os_password=$(grep ^os_password ${pf9_config} | cut -d \| -f2)
  local os_region=$(grep ^os_region ${pf9_config} | cut -d \| -f2)
  local os_tenant=$(grep ^os_tenant ${pf9_config} | cut -d \| -f2)
  local manage_hostname=$(grep ^manage_hostname ${pf9_config} | cut -d \| -f2)
  local manage_resolver=$(grep ^manage_resolver ${pf9_config} | cut -d \| -f2)
  local dns_resolver1=$(grep ^dns_resolver1 ${pf9_config} | cut -d \| -f2)
  local dns_resolver2=$(grep ^dns_resolver2 ${pf9_config} | cut -d \| -f2)
  local proxy_url=$(grep ^proxy_url ${pf9_config} | cut -d \| -f2)

  # build group_vars/all.yml
  echo "---" > ${pf9_group_vars}
  echo "# Set hostname equal to inventory_hostname" >> ${pf9_group_vars}
  echo "manage_hostname: ${manage_hostname}" >> ${pf9_group_vars}
  echo "" >> ${pf9_group_vars}
  echo "# Append DNS resolvers to /etc/resolv.conf" >> ${pf9_group_vars}
  echo "manage_resolvers: ${manage_resolver}" >> ${pf9_group_vars}
  echo "dns_resolvers:" >> ${pf9_group_vars}
  echo "  - ${dns_resolver1}" >> ${pf9_group_vars}
  echo "  - ${dns_resolver2}" >> ${pf9_group_vars}
  echo "" >> ${pf9_group_vars}
  echo "# These variables are required to be filled in for the end-user's environment" >> ${pf9_group_vars}
  echo "os_username: ${os_username}" >> ${pf9_group_vars}
  echo "os_password: '${os_password}'" >> ${pf9_group_vars}
  echo "os_region: ${os_region}" >> ${pf9_group_vars}
  echo "os_tenant: ${os_tenant}" >> ${pf9_group_vars}
  echo "du_url: ${du_url}" >> ${pf9_group_vars}
}

validate_config() {
  if [ ! -r ${pf9_config} ]; then assert "config file missing"; fi

  # read all config values
  manage_hostname=$(grep ^manage_hostname ${pf9_config} | cut -d \| -f2)
  manage_resolver=$(grep ^manage_resolver ${pf9_config} | cut -d \| -f2)
  dns_resolver1=$(grep ^dns_resolver1 ${pf9_config} | cut -d \| -f2)
  dns_resolver2=$(grep ^dns_resolver2 ${pf9_config} | cut -d \| -f2)
  os_tenant=$(grep ^os_tenant ${pf9_config} | cut -d \| -f2)
  du_url=$(grep ^du_url ${pf9_config} | cut -d \| -f2)
  os_username=$(grep ^os_username ${pf9_config} | cut -d \| -f2)
  os_password=$(grep ^os_password ${pf9_config} | cut -d \| -f2)
  os_region=$(grep ^os_region ${pf9_config} | cut -d \| -f2)
  proxy_url=$(grep ^proxy_url ${pf9_config} | cut -d \| -f2)

  # validate manage_hostname
  if [ -z "${manage_hostname}" ]; then assert "config:manage_hostname : illegal value - run './pf9-express -s'\n"; fi
  case ${manage_hostname} in
  true|false|True|False)
    ;;
  *)
    assert "config:manage_hostname : illegal value - run './pf9-express -s'\n" ;;
  esac

  # validate manage_resolver
  if [ -z "${manage_resolver}" ]; then assert "config:manage_resolver : illegal value - run './pf9-express -s'\n"; fi
  case ${manage_resolver} in
  true|false|True|False)
    ;;
  *)
    assert "config:manage_resolver : illegal value - run './pf9-express -s'\n" ;;
  esac

  # validate dns_resolver1
  if [ -z "${dns_resolver1}" ]; then assert "config:dns_resolver1 : illegal value - run './pf9-express -s'\n"; fi

  # validate dns_resolver2
  if [ -z "${dns_resolver2}" ]; then assert "config:dns_resolver2 : illegal value - run './pf9-express -s'\n"; fi

  # validate os_tenant
  if [ -z "${os_tenant}" ]; then assert "config:os_tenant : illegal value - run './pf9-express -s'\n"; fi

  # validate du_url
  if [ -z "${du_url}" ]; then assert "config:du_url : illegal value - run './pf9-express -s'\n"; fi

  # validate os_username
  if [ -z "${os_username}" ]; then assert "config:os_username : illegal value - run './pf9-express -s'\n"; fi

  # validate os_password
  if [ -z "${os_password}" ]; then assert "config:os_password : illegal value - run './pf9-express -s'\n"; fi

  # validate os_region
  if [ -z "${os_region}" ]; then assert "config:os_region : illegal value - run './pf9-express -s'\n"; fi
}
