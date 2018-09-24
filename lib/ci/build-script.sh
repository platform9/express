#!/bin/bash

# globals
exec_pf9_builder="./lib/pf9-builder/pf9-builder --nova lib/ci/kvm.centos.cfe.csv lib/ci/cfe.rc"
exec_pf9_express="./pf9-express"

echo "############################################################"
echo "### RUNNING - PF9-Express CI Build Script"
echo "############################################################"
echo "--> Date   : $(date -u)"
echo "--> Branch : Branch: $(git branch | grep ^*)"
echo "--> Directory : $(pwd)"

# install/configure pf9-express
cp -f lib/ci/cfe.rc pf9-openstack.rc
cp -f lib/ci/pf9-express.conf pf9-express.conf
eval ${exec_pf9_express} -i
eval ${exec_pf9_express} -o

# create OpenStack instances and run pf9-express
echo "exec: ${exec_pf9_builder}"
eval ${exec_pf9_builder}

# run validation tests (pf9-snitch)

# cleanup

# exit
exit 0
