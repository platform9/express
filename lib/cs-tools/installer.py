import os
import sys
from os.path import expanduser

def fail(m=None):
    sys.stdout.write("ASSERT: {}\n".format(m))
    sys.exit(1)

if not sys.version_info[0] in (2,3):
    fail("Unsupported Python Version: {}\n".format(sys.version_info[0]))

# module imports
try:
    import requests,urllib3,json,argparse,signal,prettytable,getpass
except:
    fail("Failed to import module\n{}".format(sys.exc_info()))

from prettytable import PrettyTable

# disable ssl warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# functions
def read_kbd(user_prompt, allowed_values, default_value, flag_echo=True):
    if flag_echo == True:
        input_is_valid = False
        while not input_is_valid:
            if sys.version_info[0] == 3:
                user_input = input("{} [{}]: ".format(user_prompt,default_value))
            if sys.version_info[0] == 2:
                user_input = raw_input("{} [{}]: ".format(user_prompt,default_value))

            if user_input == "":
                user_input = default_value
                input_is_valid = True
            else:
                if len(allowed_values) == 0:
                    input_is_valid = True
                else:
                    if user_input in allowed_values:
                        input_is_valid = True
    else:
        user_input = getpass.getpass(prompt="{}: ".format(user_prompt), stream=None)

    return(user_input)


def login(du_host, username, password, project_name):
    url = "{}/keystone/v3/auth/tokens?nocatalog".format(du_host)
    body = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": username,
                        "domain": {"id": "default"},
                        "password": password
                    }
                }
            },
            "scope": {
                "project": {
                    "name": project_name,
                    "domain": {"id": "default"}
                }
            }
        }
    }
    try:
        resp = requests.post(url, data=json.dumps(body), headers={'content-type': 'application/json'}, verify=False)
        json_response = json.loads(resp.text)
    except:
        fail_bootstrap("failed to parse json result")
    return json_response['token']['project']['id'], resp.headers['X-Subject-Token']


def login_du(du_url,du_user,du_password,du_tenant):
    try:
        project_id, token = login(du_url, du_user, du_password, du_tenant)
    except:
        return(None,None)

    return(project_id, token)


def get_du_creds():
    du_metadata = {}
    du_metadata['du_url'] = read_kbd("--> DU URL", [], '', True)
    du_metadata['du_user'] = read_kbd("--> DU Username", [], 'admin@platform9.net', True)
    du_metadata['du_password'] = read_kbd("--> DU Password", [], '', False)
    du_metadata['du_tenant'] = read_kbd("--> DU Tenant", [], 'service', True)
    du_metadata['region_name'] = read_kbd("--> Region Name", [], '', True)
    du_metadata['region_proxy'] = read_kbd("--> Proxy", [], '', True)
    du_metadata['region_dns'] = read_kbd("--> DNS Server (comma-delimited list or IPs)", [], '', True)

    du_metadata['region_auth_type'] = read_kbd("--> Authentication Type ['simple','ssh-key']", ['simple','ssh-key'], 'simple', True)
    du_metadata['auth_username'] = read_kbd("--> Username for Remote Access", [], '', True)
    if du_metadata['region_auth_type'] == "simple":
        du_metadata['auth_password'] = read_kbd("--> Password for Remote Access", [], '', False)
    else:
        du_metadata['auth_password'] = ""
  
    if du_metadata['region_auth_type'] == "ssh-key":
        du_metadata['auth_ssh_key'] = read_kbd("--> SSH Key for Remote Access", [], '', True)
    else:
        du_metadata['auth_ssh_key'] = ""

    du_metadata['region_bond_if_name'] = read_kbd("--> Interface Name (for OVS Bond)", [], 'bond0', True)
    du_metadata['region_bond_mode'] = read_kbd("--> Bond Mode", [], '1', True)
    du_metadata['region_bond_mtu'] = read_kbd("--> MTU for Bond Interface", [], '9000', True)
    return(du_metadata)


def qbert_is_responding(du_url, project_id, token):
    try:
        api_endpoint = "qbert/v3/{}/nodes".format(project_id)
        headers = { 'content-type': 'application/json', 'X-Auth-Token': token }
        pf9_response = requests.get("{}/{}".format(du_url,api_endpoint), verify=False, headers=headers)
        if pf9_response.status_code == 200:
            return True
    except:
        return False

    return False


def credsmanager_is_responding(du_url, project_id, token):
    try:
        api_endpoint = "credsmanager"
        headers = { 'content-type': 'application/json', 'X-Auth-Token': token }
        pf9_response = requests.get("{}/{}".format(du_url,api_endpoint), verify=False, headers=headers, timeout=5)
        if pf9_response.status_code == 200:
            return True
    except:
        return False

    return False


def get_du_hosts(du_url, project_id, token):
    num_hosts = 0
    try:
        api_endpoint = "resmgr/v1/hosts"
        headers = { 'content-type': 'application/json', 'X-Auth-Token': token }
        pf9_response = requests.get("{}/{}".format(du_url,api_endpoint), verify=False, headers=headers, timeout=5)
        if pf9_response.status_code != 200:
            return(num_hosts)

        try:
            json_response = json.loads(pf9_response.text)
        except:
            return(num_hosts)

        for item in json_response:
            num_hosts += 1
    except:
        return(num_hosts)

    return(num_hosts)


def get_du_info(du_entries):
    if not os.path.isfile(CONFIG_FILE):
        sys.stdout.write("\nNo regions have been defined yet (select 'Add Region')\n")
        return()

    du_table = PrettyTable()
    du_table.field_names = ["DU URL","Auth","Region Type","Region Name","Tenant","Proxy","# Hosts"]
    du_table.align["DU URL"] = "l"
    du_table.align["Auth"] = "l"
    du_table.align["Region Type"] = "l"
    du_table.align["Region Name"] = "l"
    du_table.align["Tenant"] = "l"
    du_table.align["Proxy"] = "l"
    du_table.align["# Hosts"] = "l"

    for du in du_entries:
        region_type = "-"
        num_hosts = "-"
        project_id, token = login_du(du['url'],du['username'],du['password'],du['tenant'])
        if token == None:
            auth_status = "Failed"
        else:
            auth_status = "OK"
            qbert_status = qbert_is_responding(du['url'], project_id, token)
            if qbert_status == True:
                region_type = "Kubernetes"
            else:
                credsmanager_status = credsmanager_is_responding(du['url'], project_id, token)
                if credsmanager_status == True:
                    region_type = "KVM"
                else:
                    region_type = "VMware"

            num_hosts = get_du_hosts(du['url'], project_id, token)

        du_table.add_row([du['url'], auth_status, region_type, du['region'], du['tenant'], du['proxy'], num_hosts])

    print(du_table)


def get_configs():
    du_configs = []
    if os.path.isfile(CONFIG_FILE):
        with open(CONFIG_FILE) as json_file:
            du_configs = json.load(json_file)

    return(du_configs)


def write_config(du):
    if not os.path.isdir(CONFIG_DIR):
        try:
            os.mkdir(CONFIG_DIR)
        except:
            fail("failed to create directory: {}".format(CONFIG_DIR))

    current_config = get_configs()
    current_config.append(du)
    with open(CONFIG_FILE, 'w') as outfile:
        json.dump(current_config, outfile)


def add_region():
    sys.stdout.write("\nAdding Region:\n")
    du_metadata = get_du_creds()
    du = {
        'url': du_metadata['du_url'],
        'username': du_metadata['du_user'],
        'password': du_metadata['du_password'],
        'tenant': du_metadata['du_tenant'],
        'region': du_metadata['region_name'],
        'proxy': du_metadata['region_proxy'],
        'dns_list': du_metadata['region_dns'],
        'auth_type': du_metadata['region_auth_type'],
        'auth_ssh_key': du_metadata['auth_ssh_key'],
        'auth_password': du_metadata['auth_password'],
        'auth_username': du_metadata['auth_username'],
        'bond_ifname': du_metadata['region_bond_if_name'],
        'bond_mode': du_metadata['region_bond_mode'],
        'bond_mtu': du_metadata['region_bond_mtu']
    }

    # persist configurtion
    write_config(du)

    # return
    return(du)


def display_menu():
    sys.stdout.write("*****************************************\n")
    sys.stdout.write("**              Main Menu              **\n")
    sys.stdout.write("*****************************************\n")
    sys.stdout.write("1. Add Region\n")
    sys.stdout.write("2. Show Region\n")
    sys.stdout.write("3. Manage Hosts\n")
    sys.stdout.write("4. Onboard Hosts\n")
    sys.stdout.write("*****************************************\n")


def cmd_loop():
    user_input = ""
    while not user_input in ['q','Q']:
        display_menu()
        user_input = read_kbd("Enter Selection ('q' to quit)", [], '', True)
        if user_input == '1':
            new_du = add_region()
            new_du_list = []
            new_du_list.append(new_du)
            get_du_info(new_du_list)
        elif user_input == '2':
            du_entries = get_configs()
            get_du_info(du_entries)
        elif user_input == '3':
            None
        elif user_input == '4':
            None
        elif user_input in ['q','Q']:
            None
        else:
            sys.stdout.write("ERROR: Invalid Selection\n")
        sys.stdout.write("\n")


#####################################################################
## pf9-express.conf
#####################################################################
# manage_hostname|false
# manage_resolver|false
# dns_resolver1|8.8.8.8
# dns_resolver2|8.8.4.4
# os_tenant|svc-pmo
# du_url|https://danwright.platform9.horse
# os_username|pf9-kubeheat
# os_password|Pl@tform9
# os_region|k8s01
# proxy_url|-

#####################################################################
## pf9-express/lib/hosts
#####################################################################
# [all]
# [all:vars]
# ansible_user=ubuntu
# ansible_sudo_pass=winterwonderland
# ansible_ssh_pass=winterwonderland
# ansible_ssh_private_key_file=~/.ssh/id_rsa
# 
# manage_network=True
# bond_ifname=bond0
# bond_mode=1
# bond_mtu=9000
# 
# [bond_config]
# hv01 bond_members='eth1' bond_sub_interfaces='[{"vlanid":"100","ip":"10.0.0.11","mask":"255.255.255.0"}]'
# 
# [pmo:children]
# hypervisors
# glance
# cinder
# 
# [hypervisors]
# hv01 ansible_host=10.0.0.11 vm_console_ip=10.0.0.11 ha_cluster_ip=10.0.1.11 tunnel_ip=10.0.2.11 dhcp=on snat=on
# hv02 ansible_host=10.0.0.12 vm_console_ip=10.0.0.12 tunnel_ip=10.0.2.12 dhcp=on snat=on
# hv03 ansible_host=10.0.0.13 vm_console_ip=10.0.0.13 tunnel_ip=10.0.2.13
# hv04 ansible_host=10.0.0.14
# 
# [glance]
# hv01 glance_ip=10.0.3.11 glance_public_endpoint=True
# hv02 glance_ip=10.0.3.12
# 
# [cinder]
# hv02 cinder_ip=10.0.4.14 pvs=["/dev/sdb","/dev/sdc","/dev/sdd","/dev/sde"]
# 
# [designate]
# hv01
# 
# [pmk:children]
# k8s_master
# k8s_worker
# 
# [k8s_master]
# cv01 ansible_host=10.0.0.15
# 
# [k8s_worker]
# cv04 ansible_host=10.0.0.18 cluster_uuid=7273706d-afd5-44ea-8fbf-901ceb6bef27

## main

# globals
HOME_DIR = expanduser("~")
CONFIG_DIR = "{}/.pf9-wizard".format(HOME_DIR)
CONFIG_FILE = "{}/du.conf".format(CONFIG_DIR)

# main menu loop
cmd_loop()
