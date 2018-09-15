#!/bin/bash

echo "[ Deleting All Jobs from AWX ]"
for id in $(tower-cli job list -a -f id); do
  echo "deleting job ${id}"
  tower-cli job delete ${id}
done

exit 0
