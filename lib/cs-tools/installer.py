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
def read_kbd(user_prompt, flag_echo=True):
    user_input = ""
    if sys.version_info[0] == 2:
        while user_input == "":
            if flag_echo == True:
                user_input = raw_input("{}: ".format(user_prompt))
            else:
                user_input = getpass.getpass(prompt='--> DU Password: ', stream=None)

    if sys.version_info[0] == 3:
        while user_input == "":
            if flag_echo == True:
                user_input = input("{}: ".format(user_prompt))
            else:
                user_input = getpass.getpass(prompt='Password: ', stream=None)

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
    du_url = read_kbd("--> DU URL", True)
    du_user = read_kbd("--> DU Username", True)
    du_password = read_kbd("--> DU Password", False)
    du_tenant = read_kbd("--> DU Tenant", True)
    return(du_url,du_user,du_password,du_tenant)


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
    du_table.field_names = ["DU URL","Auth","Region Type","# Hosts"]
    du_table.align["DU URL"] = "l"
    du_table.align["Auth"] = "l"
    du_table.align["Region Type"] = "l"
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

        du_table.add_row([du['url'], auth_status, region_type, num_hosts])

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
    du_url,du_user,du_password,du_tenant = get_du_creds()
    du = {
        'url': du_url,
        'username': du_user,
        'password': du_password,
        'tenant': du_tenant
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
        user_input = read_kbd("Enter Selection ('q' to quit)")
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


## main

# globals
HOME_DIR = expanduser("~")
CONFIG_DIR = "{}/.pf9-wizard".format(HOME_DIR)
CONFIG_FILE = "{}/du.conf".format(CONFIG_DIR)

# main menu loop
cmd_loop()
