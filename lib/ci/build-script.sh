#!/bin/bash

echo "############################################################"
echo "### RUNNING - PF9-Express CI Build Script"
echo "############################################################"
echo "--> Date   : $(date -u)"
echo "--> Branch : Branch: $(git branch | grep ^*)"
echo -e "--> Directory : $(pwd)\n"

# create OpenStack instances and run pf9-express
./lib/pf9-builder/pf9-builder --nova lib/ci/kvm.centos.cfe.csv lib/ci/cfe.rc

# run validation tests (pf9-snitch)

# cleanup

# exit
exit 0
