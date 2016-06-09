#!/usr/bin/env python
import argparse
import ConfigParser
import os.path
import sys

try:
    import json
except ImportError:
    import simplejson as json

import requests

class Platform9Inventory(object):

    def __init__(self):
        self.inventory = {}
        self.read_settings()
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
        if self.pf9_keystone_file and os.path.isfile(self.pf9_keystone_file):
            try:
                os_token_file = open(self.pf9_keystone_file)
                os_token = os_token_file.read().strip()
            except Exception, err:
                raise err
        else:
            return self.empty_inventory()

        # Make get call to resmgr to get list of hosts
        if not self.pf9_du_fqdn or len(self.pf9_du_fqdn) == 0:
            return self.empty_inventory()

        url = self.pf9_du_fqdn + '/resmgr/v1/hosts'
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
        hosts = {
            'image_libraries': {
                'hosts': []
            },
            'hypervisors': {
                'hosts': []
            },
            '_meta': {
                'hostvars': dict()
            }
        }

        for host in json_response:

            if 'pf9-glance-role' in host['roles']:
                hosts['image_libraries']['hosts'].append(host['info']['hostname'])

            hosts["_meta"]["hostvars"][host['info']['hostname']] = dict()
            for key, value in host.iteritems():
                if key in ('id', 'host', 'state', 'roles'):
                    hosts["_meta"]["hostvars"][host['info']['hostname']]["pf9_" + key] = value
                # Move deeply nested vars to top level variables
                elif key in('extensions', 'hypervisor_info'):
                    if key == 'extensions':
                        hosts["_meta"]["hostvars"][host['info']['hostname']]['pf9_ips'] = value['ip_address']['data']
                    elif key == 'hypervisor_info':
                        hosts["_meta"]["hostvars"][host['info']['hostname']]['pf9_hypervisor_type'] = value['hypervisor_type']

        return hosts

    def empty_inventory(self):
        return {'_meta': {'hostvars': {}}}

    def read_cli_args(self):
        """ Read the command line args passed dot the script """
        parser = argparse.ArgumentParser()
        parser.add_argument('--list', action='store_true')
        parser.add_argument('--host', action='store')
        self.args = parser.parse_args()

    def read_settings(self):
        """ Reads the settings from the cobbler.ini file """

        config = ConfigParser.SafeConfigParser()
        config.read(os.path.dirname(os.path.realpath(__file__)) + '/../pf9.ini')

        self.pf9_du_fqdn = None
        self.pf9_keystone_file = None

        if config.has_option('pf9', 'du_fqdn'):
            self.pf9_du_fqdn = config.get('pf9', 'du_fqdn')

        if config.has_option('pf9', 'keystone_file'):
            self.pf9_keystone_file = config.get('pf9', 'keystone_file')

Platform9Inventory()
