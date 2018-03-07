#!/bin/bash

assert() {
  if [ $# -eq 1 ]; then
    echo -e "ASSERT : ${1}"
  else
    echo -e "ASSERT : "
  fi
  exit 1
}

in_array() {
  if [ $# -eq 0 ]; then return 1; fi

  local key=${1}
  shift; defined_values=("$@")

  for value in "${defined_values[@]}"; do
    if [ "${value}" == "${key}" ]; then return 0; fi
  done

  return 1
}

getYN() {
  if [ $# -ne 1 ]; then return 1; fi

  local prompt=${1}
  local flag_valid=0
  local reply
  while [ ${flag_valid} -eq 0 ]; do
    echo -n -e "${prompt}"
    read reply
    case ${reply} in
    y|n|Y|N)
      flag_valid=1
      ;;
    *)
      echo "invalid response; please enter 'y' or 'n'"
    esac
  done

  if [ "${reply}" == "Y" -o "${reply}" == "y" ]; then
    return 0
  else
    return 1
  fi
}
