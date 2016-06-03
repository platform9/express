#!/usr/bin/env python
import json
import os.path
import sys
import requests

def main(du_url, os_token):
    """
    Retrieves list of KVM hypervisors from PF9 Resource Manager API
    and returns JSON in structured format suitable for consumption by Ansible
    playbooks

    @du_url: str
    @os_token: str
    @rtype: dict
    """
    # Check if OS Token exits
    if os.path.isfile(os_token):
        try:
            os_token_file = open('files/keystone-token.txt')
            os_token = os_token_file.read().strip()
        except Exception, err:
            raise err

    # Make get call to resmgr to get list of hosts
    url = du_url + '/resmgr/v1/hosts'
    headers = {"X-AUTH-TOKEN": os_token}
    response = requests.get(url, headers=headers)
    print response
    print type(response)
    exit(1)
    # .json()

    # Restructure JSON for Ansible
    hosts = {}
    for host in response:
        hosts[host['info']['hostname']] = dict(
            id=host['id'],
            state=host['state'],
            hypervisor_type=host['hypervisor_info']['hypervisor_type'],
            roles=host['roles'],
            ips=host['extensions']['ip_address']['data']
        )

    # Debug
    print json.dumps(hosts)

    # Write host json data out to file
    with open('files/hosts.json', 'w') as outfile:
        json.dump(hosts, outfile)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print "dyn-inv.py <du_url> <os_token_filename>"
        exit(1)

    main(sys.argv[1], sys.argv[2])
