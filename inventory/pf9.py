#!/usr/bin/env python
import argparse
import os.path
import sys

try:
    import json
except ImportError:
    import simplejson as json

import requests

KEYSTONE_TOKEN = "files/keystone-token.txt"
DU_URL = ""

class Platform9Inventory(object):

    def __init__(self):
        self.inventory = {}
        self.read_cli_args()

        # Called with '--list'
        if self.args.list:
            self.inventory = self.get_du_inventory()
        # Called with '--host hostname'
        elif self.args.host:
            # Not implemented, since we return _meta info '--list'
            self.inventory = self.empty_inventory()
        # If no groups or vars are present, return an empty inventory
        else:
            self.inventory = self.empty_inventory()

        print json.dumps(self.inventory)

    def get_du_inventory(self):
        """
        Retrieves list of KVM hypervisors from PF9 Resource Manager API
        and returns JSON in structured format suitable for consumption by Ansible
        playbooks

        @du_url: str
        @os_token: str
        @rtype: dict
        """
        # Check if OS Token exits
        if os.path.isfile(KEYSTONE_TOKEN):
            try:
                os_token_file = open(KEYSTONE_TOKEN)
                os_token = os_token_file.read().strip()
            except Exception, err:
                raise err
        else:
            return self.empty_inventory()

        # Make get call to resmgr to get list of hosts
        if not DU_URL or len(DU_URL) == 0:
            return self.empty_inventory()

        url = DU_URL + '/resmgr/v1/hosts'
        headers = {"X-AUTH-TOKEN": os_token}

        try:
            response = requests.get(url, headers=headers)
        except requests.exceptions.MissingSchema as err:
            response = requests.get("https://%s" % url, headers=headers)
        except Exception, err:
            return self.empty_inventory()

        # Return empty inventory if token is not good
        if response.status_code != 200:
            return self.empty_inventory()

        # Read JSON body
        json_response = response.json()

        # Restructure JSON for Ansible
        hosts = dict(
            _meta={
                "hostvars": dict()
            }
        )
        for host in json_response:
            hosts["_meta"]["hostvars"][host['info']['hostname']] = dict(
                pf9=dict(
                    id=host['id'],
                    state=host['state'],
                    hypervisor_type=host['hypervisor_info']['hypervisor_type'],
                    roles=host['roles'],
                    ips=host['extensions']['ip_address']['data']
                )
            )

        return hosts

    def empty_inventory(self):
        return {'_meta': {'hostvars': {}}}

    # Read the command line args passed dot the script.
    def read_cli_args(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--list', action='store_true')
        parser.add_argument('--host', action='store')
        self.args = parser.parse_args()

Platform9Inventory()
