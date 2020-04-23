#!/bin/bash

NOVA_CONF=/opt/pf9/etc/nova/conf.d/nova_override.conf

assert() {
  if [ $# -ge 1 ]; then echo ${1}; fi
  exit 1
}

echo "[libvirt]" > $NOVA_CONF
if [ $? -ne 0 ]; then assert "failed to update ${NOVA_CONF}"; fi
echo "virt_type = qemu" >> $NOVA_CONF
echo "[libvirt]" > $NOVA_CONF
echo "libvirt_type = qemu" >> $NOVA_CONF

service pf9-ostackhost restart
if [ $? -ne 0 ]; then assert "failed to restart pf9-ostackhost"; fi

exit 0
