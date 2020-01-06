####################################################################################################
## PF9-Wizard
## Onboarding Tool for Platform9 
####################################################################################################
import os
import sys
from os.path import expanduser

################################################################################
# early functions
def fail(m=None):
    sys.stdout.write("ASSERT: {}\n".format(m))
    sys.exit(1)

if not sys.version_info[0] in (2,3):
    fail("Unsupported Python Version: {}\n".format(sys.version_info[0]))

################################################################################
# module imports
try:
    import requests,urllib3,json,argparse,prettytable,signal,getpass,argparse,subprocess,time
except:
    except_str = str(sys.exc_info()[1])
    module_name = except_str.split(' ')[-1]
    fail("Failed to import module: {} (try running 'pip install {}')".format(sys.exc_info()[1],module_name))

# disable ssl warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


################################################################################
# input functions
def _parse_args():
    ap = argparse.ArgumentParser(sys.argv[0],formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("--init", "-i", help="Initialize Configuration (delete all regions/hosts)", action="store_true")
    ap.add_argument("--region", "-r", required=False, help="import region from JSON file")
    return ap.parse_args()

def read_kbd(user_prompt, allowed_values, default_value, flag_echo=True, disallow_null=True):
    if flag_echo == True:
        input_is_valid = False
        while not input_is_valid:
            if sys.version_info[0] == 3:
                user_input = input("{} [{}]: ".format(user_prompt,default_value))
            if sys.version_info[0] == 2:
                user_input = raw_input("{} [{}]: ".format(user_prompt,default_value))

            if user_input == "":
                if disallow_null == True:
                    if default_value != "":
                        user_input = default_value
                        input_is_valid = True
                    else:
                        input_is_valid = False
                else:
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


################################################################################
# du functions
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


def get_sub_dus(du):
    project_id, token = login_du(du['url'],du['username'],du['password'],du['tenant'])
    if token == None:
        return(None,None)

    try:
        api_endpoint = "keystone/v3/services?type=regionInfo"
        headers = { 'content-type': 'application/json', 'X-Auth-Token': token }
        pf9_response = requests.get("{}/{}".format(du['url'],api_endpoint), verify=False, headers=headers)
        if pf9_response.status_code == 200:
            try:
                json_response = json.loads(pf9_response.text)
                services_id = json_response['services'][0]['id']
                if services_id:
                    api_endpoint = "keystone/v3/endpoints?service_id={}".format(services_id)
                    try:
                        pf9_subresponse = requests.get("{}/{}".format(du['url'],api_endpoint), verify=False, headers=headers)
                        if pf9_subresponse.status_code == 200:
                            try:
                                json_subresponse = json.loads(pf9_subresponse.text)
                                url_list = []
                                du_name_list = []
                                for ep in json_subresponse['endpoints']:
                                    baseurl = ep['url'].replace('https://','').split('/')[0]
                                    if not baseurl in url_list:
                                        url_list.append(baseurl)
                                        du_name_list.append(ep['region'])
                                return(url_list,du_name_list)
                            except:
                                return(None,None)
                    except:
                        return(None,None)
                return(None,None)
            except:
                return(None,None)
    except:
        return(None,None)

    return(None,None)


################################################################################
# cluster functions
def get_cluster_metadata(du, project_id, token):
    if du['du_type'] in ['KVM','VMware']:
        sys.stdout.write("Invalid region type for adding cluster ({})\n".format(du['du_type']))
        return({})

    # initialize cluster record
    cluster_metadata = {}
    cluster_metadata['record_source'] = "User-Defined"
    cluster_metadata['du_url'] = du['url']
    cluster_metadata['name'] = read_kbd("--> Cluster Name", [], '', True, True)
    if cluster_metadata['name'] == "q":
        return({})

    # get current cluster settings (if already defined)
    cluster_settings = get_cluster_record(du['url'], cluster_metadata['name'])
    if cluster_settings:
        name = cluster_settings['name']
        containers_cidr = cluster_settings['containers_cidr']
        services_cidr = cluster_settings['services_cidr']
        master_vip_ipv4 = cluster_settings['master_vip_ipv4']
        master_vip_iface = cluster_settings['master_vip_iface']
        metallb_cidr = cluster_settings['metallb_cidr']
        privileged = cluster_settings['privileged']
        app_catalog_enabled = cluster_settings['app_catalog_enabled']
        allow_workloads_on_master = cluster_settings['allow_workloads_on_master']
    else:
        containers_cidr = "192.168.0.0/16"
        services_cidr = "192.169.0.0/16"
        master_vip_ipv4 = ""
        master_vip_iface = "eth0"
        metallb_cidr = ""
        privileged = "1"
        app_catalog_enabled = "0"
        allow_workloads_on_master = "0"

    cluster_metadata['containers_cidr'] = read_kbd("--> Containers CIDR", [], containers_cidr, True, True)
    if cluster_metadata['containers_cidr'] == "q":
        return({})
    cluster_metadata['services_cidr'] = read_kbd("--> Services CIDR", [], services_cidr, True, True)
    if cluster_metadata['services_cidr'] == "q":
        return({})
    cluster_metadata['master_vip_ipv4'] = read_kbd("--> Master VIP", [], master_vip_ipv4, True, True)
    if cluster_metadata['master_vip_ipv4'] == "q":
        return({})
    cluster_metadata['master_vip_iface'] = read_kbd("--> Interface Name for VIP", [], master_vip_iface, True, True)
    if cluster_metadata['master_vip_iface'] == "q":
        return({})
    cluster_metadata['metallb_cidr'] = read_kbd("--> IP Range for MetalLB", [], metallb_cidr, True, True)
    if cluster_metadata['metallb_cidr'] == "q":
        return({})
    cluster_metadata['privileged'] = read_kbd("--> Privileged API Mode", ['0','1'], privileged, True, True)
    if cluster_metadata['privileged'] == "q":
        return({})
    cluster_metadata['app_catalog_enabled'] = read_kbd("--> Enable Helm Application Catalog", ['0','1'], app_catalog_enabled, True, True)
    if cluster_metadata['app_catalog_enabled'] == "q":
        return({})
    cluster_metadata['allow_workloads_on_master'] = read_kbd("--> Enable Workloads on Master Nodes", ['0','1'], allow_workloads_on_master, True, True)
    if cluster_metadata['allow_workloads_on_master'] == "q":
        return({})

    return(cluster_metadata)


################################################################################
# host functions
def get_host_metadata(du, project_id, token):
    if du['du_type'] == "KVM":
        du_host_type = "kvm"
    elif du['du_type'] == "Kubernetes":
        du_host_type = "kubernetes"
    elif du['du_type'] == "KVM/Kubernetes":
        du_host_type = read_kbd("--> Host Type ['kvm','kubernetes']", ['kvm','kubernetes'], 'kvm', True, True)
        if du_host_type == "q":
            return({})

    # initialize host record
    host_metadata = {}
    host_metadata['record_source'] = "User-Defined"
    host_metadata['du_host_type'] = du_host_type
    host_metadata['hostname'] = read_kbd("--> Hostname", [], '', True, True)
    if host_metadata['hostname'] == "q":
        return({})

    # get current host settings (if already defined)
    host_settings = get_host_record(du['url'], host_metadata['hostname'])
    if host_settings:
        host_ip = host_settings['ip']
        host_ip_interfaces = host_settings['ip_interfaces']
        host_bond_config = host_settings['bond_config']
        host_nova = host_settings['nova']
        host_glance = host_settings['glance']
        host_cinder = host_settings['cinder']
        host_designate = host_settings['designate']
        host_node_type = host_settings['node_type']
        host_pf9_kube = host_settings['pf9-kube']
        host_cluster_name = host_settings['cluster_name']
        host_metadata['ip_interfaces'] = host_settings['ip_interfaces']
        host_metadata['uuid'] = host_settings['uuid']
    else:
        host_ip = ""
        host_bond_config = ""
        host_nova = "y"
        host_glance = "n"
        host_cinder = "n"
        host_designate = "n"
        host_node_type = ""
        host_pf9_kube = "n"
        host_cluster_name = ""
        host_metadata['ip_interfaces'] = ""
        host_metadata['uuid'] = ""

    host_metadata['ip'] = read_kbd("--> Primary IP Address", [], host_ip, True, True)
    if host_metadata['ip'] == "q":
        return({})
    if du_host_type == "kvm":
        host_metadata['bond_config'] = read_kbd("--> Bond Config", [], host_bond_config, True, False)
        if host_metadata['bond_config'] == "q":
            return({})
        host_metadata['nova'] = read_kbd("--> Enable Nova", ['y','n'], host_nova, True, True)
        if host_metadata['nova'] == "q":
            return({})
        host_metadata['glance'] = read_kbd("--> Enable Glance", ['y','n'], host_glance, True, True)
        if host_metadata['glance'] == "q":
            return({})
        host_metadata['cinder'] = read_kbd("--> Enable Cinder", ['y','n'], host_cinder, True, True)
        if host_metadata['cinder'] == "q":
            return({})
        host_metadata['designate'] = read_kbd("--> Enable Designate", ['y','n'], host_designate, True, True)
        if host_metadata['designate'] == "q":
            return({})
        host_metadata['node_type'] = ""
        host_metadata['pf9-kube'] = "n"
        host_metadata['cluster_name'] = ""
    elif du_host_type == "kubernetes":
        host_metadata['bond_config'] = ""
        host_metadata['nova'] = ""
        host_metadata['glance'] = ""
        host_metadata['cinder'] = ""
        host_metadata['designate'] = ""
        host_metadata['pf9-kube'] = "y"
        host_metadata['node_type'] = read_kbd("--> Node Type [master, worker]", ['master','worker'], host_node_type, True, True)
        if host_metadata['node_type'] == "q":
            return({})
        host_metadata['cluster_name'] = read_kbd("--> Cluster to Attach To", [], host_cluster_name, True, False)
        if host_metadata['cluster_name'] == "q":
            return({})

    return(host_metadata)


################################################################################
# du/region functions
def get_du_creds(existing_du_url):
    # initialize du data structure
    du_metadata = create_du_entry()

    if existing_du_url == None:
        user_url = read_kbd("--> DU URL", [], '', True, True)
        if user_url == 'q':
            return({})
        if user_url.startswith('http://'):
            user_url = user_url.replace('http://','https://')
        if not user_url.startswith('https://'):
            user_url = "https://{}".format(user_url)
    else:
        user_url = existing_du_url

    du_metadata['du_url'] = user_url
    du_settings = get_du_metadata(du_metadata['du_url'])

    # define du types
    du_types = [
        'KVM',
        'Kubernetes',
        'KVM/Kubernetes',
        'VMware'
    ]

    if du_settings:
        selected_du_type = du_settings['du_type']
        du_user = du_settings['username']
        du_password = du_settings['password']
        du_tenant = du_settings['tenant']
        git_branch = du_settings['git_branch']
        region_name = du_settings['region']
        region_proxy = du_settings['region_proxy']
        region_dns = du_settings['dns_list']
        region_auth_type = du_settings['auth_type']
        auth_ssh_key = du_settings['auth_ssh_key']
        auth_password = du_settings['auth_password']
        auth_username = du_settings['auth_username']
        region_bond_if_name = du_settings['bond_ifname']
        region_bond_mode = du_settings['bond_mode']
        region_bond_mtu = du_settings['bond_mtu']
    else:
        selected_du_type = ""
        du_user = "pf9-kubeheat"
        du_password = ""
        du_tenant = "svc-pmo"
        git_branch = "master"
        region_name = ""
        region_proxy = "-"
        region_dns = "8.8.8.8,8.8.4.4"
        region_auth_type = "sshkey"
        auth_ssh_key = "~/.ssh/id_rsa"
        auth_password = ""
        auth_username = "centos"
        region_bond_if_name = "bond0"
        region_bond_mode = "1"
        region_bond_mtu = "9000"

    # prompt for du type
    cnt = 1
    allowed_values = ['q']
    for target_type in du_types:
        sys.stdout.write("    {}. {}\n".format(cnt,target_type))
        allowed_values.append(str(cnt))
        cnt += 1
    user_input = read_kbd("--> Region Type", allowed_values, selected_du_type, True, True)
    if user_input == 'q':
        return({})
    else:
        if sys.version_info[0] == 2:
            if type(user_input) is unicode:
                idx = du_types.index(selected_du_type)
            else:
                idx = int(user_input) - 1
        else:
            if type(user_input) == str:
                idx = du_types.index(selected_du_type)
            else:
                idx = int(user_input) - 1
        selected_du_type = du_types[idx]

    # set du type
    du_metadata['du_type'] = selected_du_type
    du_metadata['region_name'] = ""

    # get common du parameters
    du_metadata['du_user'] = read_kbd("--> DU Username", [], du_user, True, True)
    if du_metadata['du_user'] == 'q':
        return({})
    du_metadata['du_password'] = read_kbd("--> DU Password", [], du_password, False, True)
    if du_metadata['du_password'] == 'q':
        return({})
    du_metadata['du_tenant'] = read_kbd("--> DU Tenant", [], du_tenant, True, True)
    if du_metadata['du_tenant'] == 'q':
        return({})
    du_metadata['git_branch'] = read_kbd("--> GIT Branch (for PF9-Express)", [], git_branch, True, True)
    if du_metadata['git_branch'] == 'q':
        return({})
    #du_metadata['region_name'] = read_kbd("--> Region Name", [], region_name, True, True)
    #if du_metadata['region_name'] == 'q':
    #    return({})
    du_metadata['region_auth_type'] = read_kbd("--> Authentication Type ['simple','sshkey']", ['simple','sshkey'], region_auth_type, True, True)
    if du_metadata['region_auth_type'] == 'q':
        return({})
    du_metadata['auth_username'] = read_kbd("--> Username for Remote Access", [], auth_username, True, True)
    if du_metadata['auth_username'] == 'q':
        return({})
    if du_metadata['region_auth_type'] == "simple":
        du_metadata['auth_password'] = read_kbd("--> Password for Remote Access", [], auth_password, False, True)
        if du_metadata['auth_password'] == 'q':
            return({})
    else:
        du_metadata['auth_password'] = ""
  
    if du_metadata['region_auth_type'] == "sshkey":
        du_metadata['auth_ssh_key'] = read_kbd("--> SSH Key for Remote Access", [], auth_ssh_key, True, True)
        if du_metadata['auth_ssh_key'] == 'q':
            return({})
    else:
        du_metadata['auth_ssh_key'] = ""

    # get du-specific parameters
    if selected_du_type in ['KVM','KVM/Kubernetes']:
        du_metadata['region_proxy'] = read_kbd("--> Proxy", [], region_proxy, True, True)
        if du_metadata['region_proxy'] == 'q':
            return({})
        du_metadata['region_dns'] = read_kbd("--> DNS Server (comma-delimited list or IPs)", [], region_dns, True, True)
        if du_metadata['region_dns'] == 'q':
            return({})
        du_metadata['region_bond_if_name'] = read_kbd("--> Interface Name (for OVS Bond)", [], region_bond_if_name, True, True)
        if du_metadata['region_bond_if_name'] == 'q':
            return({})
        du_metadata['region_bond_mode'] = read_kbd("--> Bond Mode", [], region_bond_mode, True, True)
        if du_metadata['region_bond_mode'] == 'q':
            return({})
        du_metadata['region_bond_mtu'] = read_kbd("--> MTU for Bond Interface", [], region_bond_mtu, True, True)
        if du_metadata['region_bond_mtu'] == 'q':
            return({})
    else:
        du_metadata['region_proxy'] = ""
        du_metadata['region_dns'] = ""
        du_metadata['region_bond_if_name'] = ""
        du_metadata['region_bond_mode'] = ""
        du_metadata['region_bond_mtu'] = ""

    return(du_metadata)


################################################################################
# api functions
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


def qbert_get_nodetype(du_url, project_id, token, node_uuid):
    node_type = ""
    try:
        api_endpoint = "qbert/v3/{}/nodes/{}".format(project_id, node_uuid)
        headers = { 'content-type': 'application/json', 'X-Auth-Token': token }
        pf9_response = requests.get("{}/{}".format(du_url,api_endpoint), verify=False, headers=headers)
        if pf9_response.status_code == 200:
            try:
                json_response = json.loads(pf9_response.text)
                if json_response['isMaster'] == 1:
                    return("master")
                else:
                    return("worker")

            except:
                return(node_type)
    except:
        return node_type

    return node_type


def qbert_get_primary_ip(du_url, project_id, token, node_uuid):
    primary_ip = ""
    try:
        api_endpoint = "qbert/v3/{}/nodes/{}".format(project_id, node_uuid)
        headers = { 'content-type': 'application/json', 'X-Auth-Token': token }
        pf9_response = requests.get("{}/{}".format(du_url,api_endpoint), verify=False, headers=headers)
        if pf9_response.status_code == 200:
            try:
                json_response = json.loads(pf9_response.text)
                return(json_response['primaryIp'])
            except:
                return(primary_ip)
    except:
        return primary_ip

    return primary_ip


def qbert_get_cluster_uuid(du_url, project_id, token, node_uuid):
    cluster_uuid = ""
    try:
        api_endpoint = "qbert/v3/{}/nodes/{}".format(project_id, node_uuid)
        headers = { 'content-type': 'application/json', 'X-Auth-Token': token }
        pf9_response = requests.get("{}/{}".format(du_url,api_endpoint), verify=False, headers=headers)
        if pf9_response.status_code == 200:
            try:
                json_response = json.loads(pf9_response.text)
                return(json_response['clusterUuid'])
            except:
                return(cluster_uuid)
    except:
        return cluster_uuid

    return cluster_uuid


def qbert_get_cluster_name(du_url, project_id, token, cluster_uuid):
    cluster_name = ""
    try:
        api_endpoint = "qbert/v3/{}/clusters/{}".format(project_id, cluster_uuid)
        headers = { 'content-type': 'application/json', 'X-Auth-Token': token }
        pf9_response = requests.get("{}/{}".format(du_url,api_endpoint), verify=False, headers=headers)
        if pf9_response.status_code == 200:
            try:
                json_response = json.loads(pf9_response.text)
                return(json_response['name'])
            except:
                return(cluster_name)
    except:
        return cluster_name

    return cluster_name


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


def get_du_type(du_url, project_id, token):
    region_type = "-"
    qbert_status = qbert_is_responding(du_url, project_id, token)
    if qbert_status == True:
        region_type = "Kubernetes"
        credsmanager_status = credsmanager_is_responding(du_url, project_id, token)
        if credsmanager_status == True:
            region_type = "KVM/Kubernetes"
        else:
            region_type = "VMware"
    else:
        credsmanager_status = credsmanager_is_responding(du_url, project_id, token)
        if credsmanager_status == True:
            region_type = "KVM"
        else:
            region_type = "VMware"
    return(region_type)


def discover_du_clusters(du_url, du_type, project_id, token):
    discovered_clusters = []
    try:
        api_endpoint = "qbert/v3/{}/clusters".format(project_id)
        headers = { 'content-type': 'application/json', 'X-Auth-Token': token }
        pf9_response = requests.get("{}/{}".format(du_url,api_endpoint), verify=False, headers=headers)
        if pf9_response.status_code != 200:
            return(discovered_clusters)
    except:
        return(discovered_clusters)

    # parse resmgr response
    try:
        json_response = json.loads(pf9_response.text)
    except:
        return(discovered_clusters)

    # process discovered clusters
    for cluster in json_response:
        cluster_record = create_cluster_entry()
        cluster_record['du_url'] = du_url
        cluster_record['name'] = cluster['name']
        cluster_record['uuid'] = cluster['uuid']
        cluster_record['record_source'] = "Discovered"
        cluster_record['containers_cidr'] = cluster['containersCidr']
        cluster_record['services_cidr'] = cluster['servicesCidr']
        cluster_record['master_vip_ipv4'] = cluster['masterVipIpv4']
        cluster_record['master_vip_iface'] = cluster['masterVipIface']
        cluster_record['metallb_cidr'] = cluster['metallbCidr']
        cluster_record['privileged'] = cluster['privileged']
        cluster_record['app_catalog_enabled'] = cluster['appCatalogEnabled']
        cluster_record['allow_workloads_on_master'] = cluster['allowWorkloadsOnMaster']
        discovered_clusters.append(cluster_record)

    return(discovered_clusters)


def discover_du_hosts(du_url, du_type, project_id, token):
    discovered_hosts = []
    try:
        api_endpoint = "resmgr/v1/hosts"
        headers = { 'content-type': 'application/json', 'X-Auth-Token': token }
        pf9_response = requests.get("{}/{}".format(du_url,api_endpoint), verify=False, headers=headers)
        if pf9_response.status_code != 200:
            return(discovered_hosts)
    except:
        return(discovered_hosts)

    # parse resmgr response
    try:
        json_response = json.loads(pf9_response.text)
    except:
        return(discovered_hosts)

    # process discovered hosts
    cnt = 0
    for host in json_response:
        # get IP
        try:
            discover_ips = ",".join(host['extensions']['ip_address']['data'])
        except:
            discover_ips = "no-data"

        # get roles
        role_kube = "n"
        role_nova = "n"
        role_glance = "n"
        role_cinder = "n"
        role_designate = "n"
        for role in host['roles']:
            if role == "pf9-kube":
                role_kube = "y"
            if role == "pf9-glance-role":
                role_glance = "y"
            if role == "pf9-cindervolume-base":
                role_cinder = "y"
            if role == "pf9-ostackhost-neutron":
                role_nova = "y"
            if role == "pf9-designate":
                role_designate = "y"

        qbert_nodetype = qbert_get_nodetype(du_url, project_id, token, host['id'])
        qbert_primary_ip = qbert_get_primary_ip(du_url, project_id, token, host['id'])
        qbert_cluster_uuid = qbert_get_cluster_uuid(du_url, project_id, token, host['id'])
        qbert_cluster_name = qbert_get_cluster_name(du_url, project_id, token, qbert_cluster_uuid)
        if role_kube == "y":
            host_type = "kubernetes"
        else:
            host_type = "kvm"

        host_record = create_host_entry()
        host_record['du_url'] = du_url
        host_record['du_type'] = du_type
        host_record['ip'] = qbert_primary_ip
        host_record['uuid'] = host['id']
        host_record['ip_interfaces'] = discover_ips
        host_record['du_host_type'] = host_type
        host_record['hostname'] = host['info']['hostname']
        host_record['record_source'] = "Discovered"
        host_record['bond_config'] = ""
        host_record['pf9-kube'] = role_kube
        host_record['nova'] = role_nova
        host_record['glance'] = role_glance
        host_record['cinder'] = role_cinder
        host_record['designate'] = role_designate
        host_record['node_type'] = qbert_nodetype
        host_record['cluster_name'] = qbert_cluster_name
        host_record['cluster_uuid'] = qbert_cluster_uuid
        discovered_hosts.append(host_record)

    return(discovered_hosts)


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


def report_cluster_info(cluster_entries):
    from prettytable import PrettyTable

    if not os.path.isfile(CLUSTER_FILE):
        sys.stdout.write("\nNo clusters have been defined yet (run 'Add/Update Cluster')\n")
        return()

    du_table = PrettyTable()
    du_table.field_names = ["Name","Containers","Services","VIP","Interface","MetalLB","Priv","Catalog","Taint","UUID"]
    du_table.title = "Kubernetes Clusters"
    du_table.header = True
    du_table.align["Name"] = "l"
    du_table.align["Containers"] = "l"
    du_table.align["Services"] = "l"
    du_table.align["VIP"] = "l"
    du_table.align["Interface"] = "l"
    du_table.align["MetalLB"] = "l"
    du_table.align["Priv"] = "l"
    du_table.align["Catalog"] = "l"
    du_table.align["Taint"] = "l"
    du_table.align["UUID"] = "l"
    #dump_var(du_table)

    for cluster in cluster_entries:
        table_row = [
            cluster['name'],
            cluster['containers_cidr'],
            cluster['services_cidr'],
            cluster['master_vip_ipv4'],
            cluster['master_vip_iface'],
            cluster['metallb_cidr'],
            cluster['privileged'],
            cluster['app_catalog_enabled'],
            cluster['allow_workloads_on_master'],
            cluster['uuid']
        ]
        du_table.add_row(table_row)

    print(du_table)


def dump_var(target_var):
    from inspect import getmembers
    from pprint import pprint
    pprint(getmembers(target_var))


def report_du_info(du_entries):
    from prettytable import PrettyTable

    if not os.path.isfile(CONFIG_FILE):
        sys.stdout.write("\nNo regions have been defined yet (run 'Add/Update Region')\n")
        return()

    du_table = PrettyTable()
    du_table.title = "Region Configuration"
    du_table.field_names = ["DU URL","DU Auth","Region Type","Region Name","Tenant","SSH Auth Type","SSH User","# Hosts"]
    du_table.align["DU URL"] = "l"
    du_table.align["DU Auth"] = "l"
    du_table.align["Region Type"] = "l"
    du_table.align["Region Name"] = "l"
    du_table.align["Tenant"] = "l"
    du_table.align["SSH Auth Type"] = "l"
    du_table.align["SSH User"] = "l"
    du_table.align["# Hosts"] = "l"

    for du in du_entries:
        num_hosts = "-"
        project_id, token = login_du(du['url'],du['username'],du['password'],du['tenant'])
        if token == None:
            auth_status = "Failed"
            region_type = ""
        else:
            auth_status = "OK"
            if du['auth_type'] == "sshkey":
                ssh_keypass = du['auth_ssh_key']
            else:
                ssh_keypass = "********"
            num_discovered_hosts = get_du_hosts(du['url'], project_id, token)
            num_defined_hosts = get_defined_hosts(du['url'])
            num_hosts = num_discovered_hosts + num_defined_hosts

        du_table.add_row([du['url'], auth_status, du['du_type'], du['region'], du['tenant'], du['auth_type'], du['auth_username'], num_hosts])

    if str(sys.version_info[0]) == "2":
        sys.stdout.write("------ {} ------\n".format(du_table.title))
    print(du_table)


def map_yn(map_key):
    if map_key == "y":
        return("Enabled")
    elif map_key == "n":
        return("Disabled")
    else:
        return("failed-to-map")

def ssh_validate_login(du_metadata, host_ip):
    if du_metadata['auth_type'] == "simple":
        return(False)
    elif du_metadata['auth_type'] == "sshkey":
        cmd = "ssh -o StrictHostKeyChecking=no -i {} {}@{} 'echo 201'".format(du_metadata['auth_ssh_key'], du_metadata['auth_username'], host_ip)
        exit_status, stdout = run_cmd(cmd)
        if exit_status == 0:
            return(True)
        else:
            return(False)

    return(False)


def get_defined_hosts(du_url):
    num_discovered_hosts = 0

    if os.path.isfile(HOST_FILE):
        with open(HOST_FILE) as json_file:
            host_configs = json.load(json_file)
        for host in host_configs:
            if host['du_url'] == du_url:
                num_discovered_hosts += 1

    return(num_discovered_hosts)


def report_host_info(host_entries):
    from prettytable import PrettyTable

    if not os.path.isfile(HOST_FILE):
        sys.stdout.write("\nNo hosts have been defined yet (run 'Add/Update Hosts')\n")
        return()

    if len(host_entries) == 0:
        sys.stdout.write("\nNo hosts have been defined yet (run 'Add/Update Hosts')\n")
        return()
    
    du_metadata = get_du_metadata(host_entries[0]['du_url'])
    if du_metadata['du_type'] in ['KVM','KVM/Kubernetes']:
        host_table = PrettyTable()
        host_table.field_names = ["HOSTNAME","Primary IP","SSH Auth","Source","Nova","Glance","Cinder","Designate","Bond Config","IP Interfaces"]
        host_table.title = "KVM Hosts"
        host_table.align["HOSTNAME"] = "l"
        host_table.align["Primary IP"] = "l"
        host_table.align["SSH Auth"] = "l"
        host_table.align["IP Interfaces"] = "l"
        host_table.align["Source"] = "l"
        host_table.align["Nova"] = "l"
        host_table.align["Glance"] = "l"
        host_table.align["Cinder"] = "l"
        host_table.align["Designate"] = "l"
        host_table.align["Bond Config"] = "l"
        num_kvm_rows = 0
        for host in host_entries:
            if host['du_host_type'] != "kvm":
                continue
            if host['ip'] == "":
                ssh_status = "No Primary IP"
            else:
                ssh_status = ssh_validate_login(du_metadata, host['ip'])
                if ssh_status == True:
                    ssh_status = "OK"
                else:
                    ssh_status = "Failed"
            host_table.add_row([host['hostname'],host['ip'], ssh_status, host['record_source'], map_yn(host['nova']), map_yn(host['glance']), map_yn(host['cinder']), map_yn(host['designate']), host['bond_config'],host['ip_interfaces']])
            num_kvm_rows += 1

        if num_kvm_rows > 0:
            print(host_table)

    if du_metadata['du_type'] in ['Kubernetes','KVM/Kubernetes']:
        host_table = PrettyTable()
        host_table.field_names = ["HOSTNAME","Primary IP","SSH Auth","Source","Node Type","Cluster Name","IP Interfaces"]
        host_table.title = "Kubernetes Hosts"
        host_table.align["HOSTNAME"] = "l"
        host_table.align["Primary IP"] = "l"
        host_table.align["SSH Auth"] = "l"
        host_table.align["IP Interfaces"] = "l"
        host_table.align["Source"] = "l"
        host_table.align["Node Type"] = "l"
        host_table.align["Cluster Name"] = "l"
        num_k8s_rows = 0
        for host in host_entries:
            if host['du_host_type'] != "kubernetes":
                continue
            ssh_status = ssh_validate_login(du_metadata, host['ip'])
            if ssh_status == True:
                ssh_status = "OK"
            else:
                ssh_status = "Failed"

            if host['cluster_name'] == "":
                cluster_assigned = "Unassigned"
            else:
                cluster_assigned = host['cluster_name']

            host_table.add_row([host['hostname'], host['ip'], ssh_status, host['record_source'], host['node_type'], cluster_assigned, host['ip_interfaces']])
            num_k8s_rows += 1
        if num_k8s_rows > 0:
            print(host_table)


def add_edit_du():
    if not os.path.isdir(CONFIG_DIR):
        return(None)
    elif not os.path.isfile(CONFIG_FILE):
        return("define-new-du")
    else:
        current_config = get_configs()
        if len(current_config) == 0:
            return(None)
        else:
            cnt = 1
            allowed_values = ['q','n']
            sys.stdout.write("\n")
            for du in current_config:
                sys.stdout.write("{}. {}\n".format(cnt,du['url']))
                allowed_values.append(str(cnt))
                cnt += 1
            sys.stdout.write("\n")
            user_input = read_kbd("Select Region (enter 'n' to create a New Region)", allowed_values, '', True, True)
            if user_input == "q":
                return(None)
            elif user_input == "n":
                return("define-new-du")
            else:
                idx = int(user_input) - 1
                return(current_config[idx]['url'])
        return(None)


def select_du():
    if not os.path.isdir(CONFIG_DIR):
        sys.stdout.write("\nNo regions have been defined yet (run 'Add/Update Region')\n")
    elif not os.path.isfile(CONFIG_FILE):
        sys.stdout.write("\nNo regions have been defined yet (run 'Add/Update Region')\n")
    else:
        current_config = get_configs()
        if len(current_config) == 0:
            sys.stdout.write("\nNo regions have been defined yet (run 'Add/Update Region')\n")
        else:
            cnt = 1
            allowed_values = ['q']
            sys.stdout.write("\n")
            for du in current_config:
                sys.stdout.write("{}. {}\n".format(cnt,du['url']))
                allowed_values.append(str(cnt))
                cnt += 1
            user_input = read_kbd("Select Region", allowed_values, '', True, True)
            if user_input == "q":
                return({})
            else:
                idx = int(user_input) - 1
                return(current_config[idx])
        return({})


def get_configs(du_url=None):
    du_configs = []
    if os.path.isfile(CONFIG_FILE):
        with open(CONFIG_FILE) as json_file:
            du_configs = json.load(json_file)

    if not du_url:
        return(du_configs)
    else:
        filtered_du_configs = []
        for du in du_configs:
            if du['url'] == du_url:
                filtered_du_configs.append(du)
        return(filtered_du_configs)


def get_cluster_record(du_url, cluster_name):
    cluster_metadata = {}
    if os.path.isfile(CLUSTER_FILE):
        with open(CLUSTER_FILE) as json_file:
            cluster_configs = json.load(json_file)
        for cluster in cluster_configs:
            if cluster['du_url'] == du_url and cluster['name'] == cluster_name:
                cluster_metadata = dict(cluster)
                break

    return(cluster_metadata)


def get_host_record(du_url, hostname):
    host_metadata = {}
    if os.path.isfile(HOST_FILE):
        with open(HOST_FILE) as json_file:
            host_configs = json.load(json_file)
        for host in host_configs:
            if host['du_url'] == du_url and host['hostname'] == hostname:
                host_metadata = dict(host)
                break

    return(host_metadata)


def delete_du(target_du):
    new_du_list = []
    if os.path.isfile(CONFIG_FILE):
        with open(CONFIG_FILE) as json_file:
            du_configs = json.load(json_file)
        for du in du_configs:
            if du['url'] == target_du['url']:
                sys.stdout.write("--> found target DU\n")
            else:
                new_du_list.append(du)
    else:
        sys.stdout.write("\nERROR: failed to open DU database: {}".format(CONFIG_FILE))

    # update DU database
    try:
        with open(CONFIG_FILE, 'w') as outfile:
            json.dump(new_du_list, outfile)
    except:
        sys.stdout.write("\nERROR: failed to update DU database: {}".format(CONFIG_FILE))


def get_du_metadata(du_url):
    du_config = {}
    if os.path.isfile(CONFIG_FILE):
        with open(CONFIG_FILE) as json_file:
            du_configs = json.load(json_file)
        for du in du_configs:
            if du['url'] == du_url:
                du_config = dict(du)
                break

    return(du_config)


def get_clusters(du_url):
    du_clusters = []
    if os.path.isfile(CLUSTER_FILE):
        with open(CLUSTER_FILE) as json_file:
            du_clusters = json.load(json_file)

    if du_url == None:
        filtered_clusters = list(du_clusters)
    else:
        filtered_clusters = []
        for cluster in du_clusters:
            if cluster['du_url'] == du_url:
                filtered_clusters.append(cluster)

    return(filtered_clusters)


def get_hosts(du_url):
    du_hosts = []
    if os.path.isfile(HOST_FILE):
        with open(HOST_FILE) as json_file:
            du_hosts = json.load(json_file)

    if du_url == None:
        filtered_hosts = list(du_hosts)
    else:
        filtered_hosts = []
        for du in du_hosts:
            if du['du_url'] == du_url:
                filtered_hosts.append(du)

    return(filtered_hosts)


def write_cluster(cluster):
    if not os.path.isdir(CONFIG_DIR):
        try:
            os.mkdir(CONFIG_DIR)
        except:
            fail("failed to create directory: {}".format(CONFIG_DIR))

    current_clusters = get_clusters(None)
    if len(current_clusters) == 0:
        current_clusters.append(cluster)
        with open(CLUSTER_FILE, 'w') as outfile:
            json.dump(current_clusters, outfile)
    else:
        update_clusters = []
        flag_found = False
        for c in current_clusters:
            if c['name'] == cluster['name']:
                update_clusters.append(cluster)
                flag_found = True
            else:
                update_clusters.append(c)
        if not flag_found:
            update_clusters.append(cluster)
        with open(CLUSTER_FILE, 'w') as outfile:
            json.dump(update_clusters, outfile)


def write_host(host):
    if not os.path.isdir(CONFIG_DIR):
        try:
            os.mkdir(CONFIG_DIR)
        except:
            fail("failed to create directory: {}".format(CONFIG_DIR))

    current_hosts = get_hosts(None)
    if len(current_hosts) == 0:
        current_hosts.append(host)
        with open(HOST_FILE, 'w') as outfile:
            json.dump(current_hosts, outfile)
    else:
        update_hosts = []
        flag_found = False
        for h in current_hosts:
            if h['hostname'] == host['hostname']:
                update_hosts.append(host)
                flag_found = True
            else:
                update_hosts.append(h)
        if not flag_found:
            update_hosts.append(host)
        with open(HOST_FILE, 'w') as outfile:
            json.dump(update_hosts, outfile)


def write_config(du):
    if not os.path.isdir(CONFIG_DIR):
        try:
            os.mkdir(CONFIG_DIR)
        except:
            fail("failed to create directory: {}".format(CONFIG_DIR))

    current_config = get_configs()
    if len(current_config) == 0:
        current_config.append(du)
        with open(CONFIG_FILE, 'w') as outfile:
            json.dump(current_config, outfile)
    else:
        update_config = []
        flag_found = False
        for config in current_config:
            if config['url'] == du['url']:
                update_config.append(du)
                flag_found = True
            else:
                update_config.append(config)
        if not flag_found:
            update_config.append(du)
        with open(CONFIG_FILE, 'w') as outfile:
            json.dump(update_config, outfile)


def add_cluster(du):
    sys.stdout.write("\nAdding Cluster to Region: {}\n".format(du['url']))
    project_id, token = login_du(du['url'],du['username'],du['password'],du['tenant'])
    if token == None:
        sys.stdout.write("--> failed to login to region")
    else:
        cluster_metadata = get_cluster_metadata(du, project_id, token)
        if cluster_metadata:
            cluster = create_cluster_entry()
            cluster['du_url'] = cluster_metadata['du_url']
            cluster['name'] = cluster_metadata['name']
            cluster['record_source'] = "User-Defined"
            cluster['containers_cidr'] = cluster_metadata['containers_cidr']
            cluster['services_cidr'] = cluster_metadata['services_cidr']
            cluster['master_vip_ipv4'] = cluster_metadata['master_vip_ipv4']
            cluster['master_vip_iface'] = cluster_metadata['master_vip_iface']
            cluster['metallb_cidr'] = cluster_metadata['metallb_cidr']
            cluster['privileged'] = cluster_metadata['privileged']
            cluster['app_catalog_enabled'] = cluster_metadata['app_catalog_enabled']
            cluster['allow_workloads_on_master'] = cluster_metadata['allow_workloads_on_master']

            # persist configurtion
            write_cluster(cluster)


def add_host(du):
    sys.stdout.write("\nAdding Host to Region: {}\n".format(du['url']))
    project_id, token = login_du(du['url'],du['username'],du['password'],du['tenant'])
    if token == None:
        sys.stdout.write("--> failed to login to region")
    else:
        host_metadata = get_host_metadata(du, project_id, token)
        if host_metadata:
            host = create_host_entry()
            host['du_url'] = du['url']
            host['du_host_type'] = host_metadata['du_host_type']
            host['ip'] = host_metadata['ip']
            host['uuid'] = host_metadata['uuid']
            host['ip_interfaces'] = host_metadata['ip_interfaces']
            host['hostname'] = host_metadata['hostname']
            host['record_source'] = host_metadata['record_source']
            host['bond_config'] = host_metadata['bond_config']
            host['pf9-kube'] = host_metadata['pf9-kube']
            host['nova'] = host_metadata['nova']
            host['glance'] = host_metadata['glance']
            host['cinder'] = host_metadata['cinder']
            host['designate'] = host_metadata['designate']
            host['node_type'] = host_metadata['node_type']
            host['cluster_name'] = host_metadata['cluster_name']

            # persist configurtion
            write_host(host)


def create_du_entry():
    du_record = {
        'url': "",
        'du_type': "",
        'username': "",
        'password': "",
        'tenant': "",
        'git_branch': "",
        'region': "",
        'region_proxy': "",
        'dns_list': "",
        'auth_type': "",
        'auth_ssh_key': "",
        'auth_password': "",
        'auth_username': "",
        'bond_ifname': "",
        'bond_mode': "",
        'bond_mtu': ""
    }
    return(du_record)


def create_cluster_entry():
    cluster_record = {
        'du_url': "",
        'name': "",
        'record_source': "",
        'uuid': "",
        'containers_cidr': "",
        'services_cidr': "",
        'master_vip_ipv4': "",
        'master_vip_iface': "",
        'metallb_cidr': "",
        'privileged': "",
        'app_catalog_enabled': "",
        'allow_workloads_on_master': ""
    }
    return(cluster_record)


def create_host_entry():
    host_record = {
        'du_url': "",
        'du_type': "",
        'ip': "",
        'uuid': "",
        'ip_interfaces': "",
        'du_host_type': "",
        'hostname': "",
        'record_source': "",
        'bond_config': "",
        'pf9-kube': "",
        'nova': "",
        'glance': "",
        'cinder': "",
        'designate': "",
        'node_type': "",
        'cluster_name': "",
        'cluster_uuid': ""
    }
    return(host_record)


def get_nodepool_id(du_url,project_id,token):
    try:
        headers = { 'content-type': 'application/json', 'X-Auth-Token': token }
        api_endpoint = "qbert/v3/{}/cloudProviders".format(project_id)
        pf9_response = requests.get("{}/{}".format(du_url,api_endpoint), verify=False, headers=headers)
        if pf9_response.status_code != 200:
            return None

        # parse resmgr response
        try:
            json_response = json.loads(pf9_response.text)
        except:
            return None

        for item in json_response:
            if item['type'] == 'local':
                return(item['nodePoolUuid'])
    except:
        return None


def create_cluster(du_url,project_id,token,cluster):
    sys.stdout.write("--> Creating Cluster: {}\n".format(cluster['name']))
    nodepool_id = get_nodepool_id(du_url,project_id,token)
    if nodepool_id == None:
        sys.stdout.write("ERROR: failed to get nodepool_id for cloud provider\n")
        return(None)

    # configure cluster
    cluster_create_payload = {
        "name": cluster['name'],
        "nodePoolUuid": nodepool_id,
        "containersCidr": cluster['containers_cidr'],
        "servicesCidr": cluster['services_cidr'],
        "masterVipIpv4": cluster['master_vip_ipv4'],
        "masterVipIface": cluster['master_vip_iface'],
        "metallbCidr": cluster['metallb_cidr'],
        "privileged": cluster['privileged'],
        "appCatalogEnabled": cluster['app_catalog_enabled'],
        "allowWorkloadsOnMaster": cluster['allow_workloads_on_master'],
        "enableMetallb": True
    }

    # create cluster
    try:
        api_endpoint = "qbert/v3/{}/clusters".format(project_id)
        headers = { 'content-type': 'application/json', 'X-Auth-Token': token }
        pf9_response = requests.post("{}/{}".format(du_url,api_endpoint), verify=False, headers=headers, data=json.dumps(cluster_create_payload))
    except:
        sys.stdout.write("ERROR: failed to create cluster\n")
        return(None)

    # parse resmgr response
    cluster_uuid = None
    try:
        json_response = json.loads(pf9_response.text)
        cluster_uuid = json_response['uuid']
    except:
        sys.stdout.write("INFO: failed to create cluster (failed to retrieve the uuid)\n")
    return(cluster_uuid)


def cluster_in_array(target_url,target_name,target_clusters):
    for cluster in target_clusters:
        if cluster['du_url'] == target_url and cluster['name'] == target_name:
            return(True)
    return(False)


def add_region(existing_du_url):
    if existing_du_url == None:
        sys.stdout.write("\nAdding a Region:\n")
    else:
        sys.stdout.write("\nUpdate Region:\n")

    # du_metadata is created by create_du_entry() - and initialized or populated from existing du record
    du_metadata = get_du_creds(existing_du_url)
    if not du_metadata:
        return(du_metadata)
    else:
        # initialize du data structure
        du = create_du_entry()
        du['url'] = du_metadata['du_url']
        du['du_type'] = du_metadata['du_type']
        du['username'] = du_metadata['du_user']
        du['password'] = du_metadata['du_password']
        du['tenant'] = du_metadata['du_tenant']
        du['git_branch'] = du_metadata['git_branch']
        du['region'] = du_metadata['region_name']
        du['region_proxy'] = du_metadata['region_proxy']
        du['dns_list'] = du_metadata['region_dns']
        du['auth_type'] = du_metadata['region_auth_type']
        du['auth_ssh_key'] = du_metadata['auth_ssh_key']
        du['auth_password'] = du_metadata['auth_password']
        du['auth_username'] = du_metadata['auth_username']
        du['bond_ifname'] = du_metadata['region_bond_if_name']
        du['bond_mode'] = du_metadata['region_bond_mode']
        du['bond_mtu'] = du_metadata['region_bond_mtu']

    # initialize list of regions to be discovered
    discover_targets = []

    # define valid region types
    region_types = [
        "q",
        "KVM",
        "Kubernetes",
        "KVM/Kubernetes",
        "VMware"
    ]

    # check for sub-regions
    sub_regions, du_name_list = get_sub_dus(du)
    if not sub_regions:
        du['region'] = du_name_list[sub_regions.index(du_metadata['du_url'].replace('https://',''))]
        discover_targets.append(du)
    else:
        sys.stdout.write("\nThe Following Sub-Regions Have Been Detected:\n\n")
        cnt = 1
        for sub_region in sub_regions:
            if sub_region != du['url'].replace('https://',''):
                sys.stdout.write("{}. {}\n".format(cnt, sub_region))
                cnt += 1
        user_input = read_kbd("\nDo you want to discover these regions as well", ['q','y','n'], 'n', True, True)
        if user_input == "q":
            return(None)
        elif user_input == "y":
            for sub_region in sub_regions:
                sub_du = create_du_entry()
                sub_du['url'] = "https://{}".format(sub_region)
                sub_du['du_type'] = "KVM/Kubernetes"
                sub_du['region'] = du_name_list[sub_regions.index(sub_region)]
                sub_du['username'] = du_metadata['du_user']
                sub_du['password'] = du_metadata['du_password']
                sub_du['tenant'] = du_metadata['du_tenant']
                sub_du['git_branch'] = "master"
                sub_du['region_proxy'] = "-"
                sub_du['dns_list'] = "8.8.8.8,8.8.4.4"
                sub_du['auth_type'] = "sshkey"
                sub_du['auth_ssh_key'] = "~/.ssh/id_rsa"
                sub_du['auth_username'] = "centos"
                sub_du['bond_ifname'] = "bond0"
                sub_du['bond_mode'] = "1"
                sub_du['bond_mtu'] = "9000"
                discover_targets.append(sub_du)
        else:
            du['region'] = du_name_list[sub_regions.index(du_metadata['du_url'].replace('https://',''))]
            discover_targets.append(du)

    # create region (and sub-regions)
    sys.stdout.write("\nCreating Region(s):\n")
    for discover_target in discover_targets:
        project_id, token = login_du(discover_target['url'],discover_target['username'],discover_target['password'],discover_target['tenant'])
        if project_id:
            sys.stdout.write("--> Adding region: {}\n".format(discover_target['url']))
            region_type = get_du_type(discover_target['url'], project_id, token)
            if discover_target['url'] == du_metadata['du_url']:
                confirmed_region_type = read_kbd("    Confirm region type ['KVM','Kubernetes','KVM/Kubernetes','VMware']", region_types, du_metadata['du_type'], True, True)
            else:
                confirmed_region_type = read_kbd("    Confirm region type ['KVM','Kubernetes','KVM/Kubernetes','VMware']", region_types, region_type, True, True)
            discover_target['du_type'] = confirmed_region_type
            write_config(discover_target)

    # perform host discovery
    sys.stdout.write("\nPerforming Host Discovery\n")
    for discover_target in discover_targets:
        sys.stdout.write("--> Discovering hosts for region: {}\n".format(discover_target['url']))
        project_id, token = login_du(discover_target['url'],discover_target['username'],discover_target['password'],discover_target['tenant'])
        if project_id:
            discovered_hosts = discover_du_hosts(discover_target['url'], discover_target['du_type'], project_id, token)
            for host in discovered_hosts:
                write_host(host)
    sys.stdout.write("\n")

    # perform cluster discovery
    sys.stdout.write("Performing Cluster Discovery (and provisioning for user-defined clusters)\n")
    for discover_target in discover_targets:
        if discover_target['du_type'] in ['Kubernetes','KVM/Kubernetes']:
            sys.stdout.write("--> Discovering clusters for region: {}\n".format(discover_target['url']))
            project_id, token = login_du(discover_target['url'],discover_target['username'],discover_target['password'],discover_target['tenant'])
            if project_id:
                # discover existing clusters
                discovered_clusters = discover_du_clusters(discover_target['url'], discover_target['du_type'], project_id, token)

                # get existing/user-defined clusters for region
                defined_clusters = get_clusters(discover_target['url'])

                # create any missing clusters
                for cluster in defined_clusters:
                    cluster_flag = cluster_in_array(cluster['du_url'],cluster['name'],discovered_clusters)
                    if not cluster_in_array(cluster['du_url'],cluster['name'],discovered_clusters):
                        create_cluster(discover_target['url'],project_id,token,cluster)

                for cluster in discovered_clusters:
                    write_cluster(cluster)
    sys.stdout.write("\n")

    # return
    return(discover_targets)


def build_express_config(du):
    express_config = "{}/{}.conf".format(CONFIG_DIR, "{}".format(du['url'].replace('https://','')))
    sys.stdout.write("--> Building configuration file: {}\n".format(express_config))

    # write config file
    try:
        express_config_fh = open(express_config, "w")
        express_config_fh.write("manage_hostname|false\n")
        express_config_fh.write("manage_resolver|false\n")
        express_config_fh.write("dns_resolver1|8.8.8.8\n")
        express_config_fh.write("dns_resolver2|8.8.4.4\n")
        express_config_fh.write("os_tenant|{}\n".format(du['tenant']))
        express_config_fh.write("du_url|{}\n".format(du['url']))
        express_config_fh.write("os_username|{}\n".format(du['username']))
        express_config_fh.write("os_password|{}\n".format(du['password']))
        express_config_fh.write("os_region|{}\n".format(du['region']))
        express_config_fh.write("proxy_url|{}\n".format(du['region_proxy']))
        express_config_fh.close()
    except:
        sys.stdout.write("ERROR: failed to build configuration file: {}\n{}\n".format(express_config,sys.exc_info()))
        return(None)

    # validate config was written
    if not os.path.isfile(express_config):
        return(None)

    return(express_config)


def build_express_inventory(du, host_entries):
    express_inventory = "{}/{}.inv".format(CONFIG_DIR, "{}".format(du['url'].replace('https://','')))
    sys.stdout.write("--> Building inventory file: {}\n".format(express_inventory))

    # write inventory file
    try:
        express_inventory_fh = open(express_inventory, "w")
        express_inventory_fh.write("# Built by pf9-wizard\n")
        express_inventory_fh.write("[all]\n")
        express_inventory_fh.write("[all:vars]\n")
        express_inventory_fh.write("ansible_user={}\n".format(du['auth_username']))
        if du['auth_type'] == "simple":
            express_inventory_fh.write("ansible_sudo_pass={}\n".format(du['auth_password']))
            express_inventory_fh.write("ansible_ssh_pass={}\n".format(du['auth_password']))
        if du['auth_type'] == "sshkey":
            express_inventory_fh.write("ansible_ssh_private_key_file={}\n".format(du['auth_ssh_key']))
        express_inventory_fh.write("manage_network=True\n")
        express_inventory_fh.write("bond_ifname={}\n".format(du['bond_ifname']))
        express_inventory_fh.write("bond_mode={}\n".format(du['bond_mode']))
        express_inventory_fh.write("bond_mtu={}\n".format(du['bond_mtu']))

        # manage bond stanza
        express_inventory_fh.write("[bond_config]\n")
        for host in host_entries:
            if host['bond_config'] != "":
                express_inventory_fh.write("{} {}\n".format(host['hostname'], host['bond_config']))

        # manage openstack groups
        express_inventory_fh.write("[pmo:children]\n")
        express_inventory_fh.write("hypervisors\n")
        express_inventory_fh.write("glance\n")
        express_inventory_fh.write("cinder\n")

        # manage hypervisors group
        express_inventory_fh.write("[hypervisors]\n")
        cnt = 0
        for host in host_entries:
            if cnt < 2:
                express_inventory_fh.write("{} ansible_host={} vm_console_ip={} ha_cluster_ip={} tunnel_ip={} dhcp=on snat=on\n".format(host['hostname'],host['ip'],host['ip'],host['ip'],host['ip']))
            else:
                express_inventory_fh.write("{} ansible_host={} vm_console_ip={} ha_cluster_ip={} tunnel_ip={}\n".format(host['hostname'],host['ip'],host['ip'],host['ip'],host['ip']))
            cnt += 1

        # manage glance group
        express_inventory_fh.write("[glance]\n")
        cnt = 0
        for host in host_entries:
            if host['glance'] == "y":
                if cnt == 0:
                    express_inventory_fh.write("{} glance_ip={} glance_public_endpoint=True\n".format(host['hostname'],host['ip']))
                else:
                    express_inventory_fh.write("{} glance_ip={}\n".format(host['hostname'],host['ip']))
            cnt += 1

        # manage cinder group
        express_inventory_fh.write("[cinder]\n")
        for host in host_entries:
            if host['cinder'] == "y":
                express_inventory_fh.write("{} cinder_ip={} pvs=['/dev/sdb','/dev/sdc','/dev/sdd','/dev/sde']\n".format(host['hostname'],host['ip']))

        # manage designate group
        express_inventory_fh.write("[designate]\n")
        for host in host_entries:
            if host['designate'] == "y":
                express_inventory_fh.write("{}\n".format(host['hostname']))

        # manage K8s stanza
        express_inventory_fh.write("[pmk:children]\n")
        express_inventory_fh.write("k8s_master\n")
        express_inventory_fh.write("k8s_worker\n")

        # manage K8s_master stanza
        express_inventory_fh.write("[k8s_master]\n")
        for host in host_entries:
            if host['pf9-kube'] == "y" and host['node_type'] == "master":
                if host['cluster_name'] == "":
                    express_inventory_fh.write("{} ansible_host={}\n".format(host['hostname'],host['ip']))
                else:
                    express_inventory_fh.write("{} ansible_host={} cluster_uuid={}\n".format(host['hostname'],host['ip'],host['cluster_uuid']))

        # manage K8s_worker stanza
        express_inventory_fh.write("[k8s_worker]\n")
        for host in host_entries:
            if host['pf9-kube'] == "y" and host['node_type'] == "worker":
                if host['cluster_name'] == "":
                    express_inventory_fh.write("{} ansible_host={}\n".format(host['hostname'],host['ip']))
                else:
                    express_inventory_fh.write("{} ansible_host={} cluster_uuid={}\n".format(host['hostname'],host['ip'],host['cluster_uuid']))
  
        # close inventory file
        express_inventory_fh.close()
    except:
        return(None)

    # validate inventory was written
    if not os.path.isfile(express_inventory):
        return(None)

    return(express_inventory)


def checkout_branch(git_branch):
    cmd = "cd {} && git checkout {}".format(EXPRESS_INSTALL_DIR, git_branch)
    exit_status, stdout = run_cmd(cmd)

    current_branch = get_express_branch(git_branch)
    if current_branch != git_branch:
        return(False)

    return(True)


def get_express_branch(git_branch):
    if not os.path.isdir(EXPRESS_INSTALL_DIR):
        return(None)

    cmd = "cd {} && git symbolic-ref --short -q HEAD".format(EXPRESS_INSTALL_DIR)
    exit_status, stdout = run_cmd(cmd)
    if exit_status != 0:
        return(none)

    return(stdout[0].strip())
    

def install_express(du):
    sys.stdout.write("\n[Install/Update PF9-Express]\n")
    if not os.path.isdir(EXPRESS_INSTALL_DIR):
        cmd = "git clone {} {}".format(EXPRESS_REPO, EXPRESS_INSTALL_DIR)
        sys.stdout.write("--> running: {}\n".format(cmd))
        exit_status, stdout = run_cmd(cmd)
        if not os.path.isdir(EXPRESS_INSTALL_DIR):
            sys.stdout.write("ERROR: failed to clone PF9-Express Repository\n")
            return(False)

    cmd = "cd {}; git fetch -a".format(EXPRESS_INSTALL_DIR)
    exit_status, stdout = run_cmd(cmd)
    sys.stdout.write("--> running: {}\n".format(cmd))
    if exit_status != 0:
        sys.stdout.write("ERROR: failed to fetch branches (git fetch -)\n")
        return(False)

    current_branch = get_express_branch(du['git_branch'])
    sys.stdout.write("--> current branch: {}\n".format(current_branch))
    if current_branch != du['git_branch']:
        if (checkout_branch(du['git_branch'])) == False:
            sys.stdout.write("ERROR: failed to checkout git branch: {}\n".format(du['git_branch']))
            return(False)

    cmd = "cd {}; git pull origin {}".format(EXPRESS_INSTALL_DIR,du['git_branch'])
    sys.stdout.write("--> running: {}\n".format(cmd))
    exit_status, stdout = run_cmd(cmd)
    if exit_status != 0:
        sys.stdout.write("ERROR: failed to pull latest code (git pull origin {})\n".format(du['git_branch']))
        return(False)
 
    return(True)


def wait_for_job(p):
    cnt = 0
    minute = 1
    while True:
        if cnt == 0:
            sys.stdout.write(".")
        elif (cnt % 9) == 0:
            sys.stdout.write("|")
            if (minute % 6) == 0:
                sys.stdout.write("\n")
            cnt = -1
            minute += 1
        else:
            sys.stdout.write(".")
        sys.stdout.flush()
        if p.poll() != None:
            break
        time.sleep(1)
        cnt += 1
    sys.stdout.write("\n")


def tail_log(p):
    last_line = None
    while True:
        current_line = p.stdout.readline()
        if sys.version_info[0] == 2:
            sys.stdout.write(current_line)
        else:
            sys.stdout.write(str(current_line))
        if p.poll() != None:
            if current_line == last_line:
                sys.stdout.write("-------------------- PROCESS COMPETE --------------------\n")
                break
        last_line = current_line


def invoke_express(express_config, express_inventory, target_inventory, role_flag):
    # manage '--pmk' flag (for pf9-express invocation)
    if target_inventory in ['k8s_master','ks8_worker']:
        flags = "--pmk"
    else:
        flags = ""

    user_input = read_kbd("--> Installing PF9-Express Prerequisites, do you want to tail the log (enter 's' to skip)", ['q','y','n','s'], 'n', True, True)
    if user_input == 'q':
        return()
    if user_input in ['y','n']:
        p = subprocess.Popen([PF9_EXPRESS,'-i','-c',express_config],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if user_input == 'y':
            sys.stdout.write("----------------------------------- Start Log -----------------------------------\n")
            tail_log(p)
        else:
            wait_for_job(p)

    user_input = read_kbd("--> Running PF9-Express, do you want to tail the log", ['q','y','n'], 'n', True, True)
    if user_input == 'q':
        return()
    if role_flag == 1:
        sys.stdout.write("Running: {} {} -a -b -c {} -v {} {}\n".format(PF9_EXPRESS,flags,express_config,express_inventory,target_inventory))
        p = subprocess.Popen([PF9_EXPRESS,flags,'-a','-b','-c',express_config,'-v',express_inventory,target_inventory],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    else:
        sys.stdout.write("Running: {} {} -b -c {} -v {} {}\n".format(PF9_EXPRESS,flags,express_config,express_inventory,target_inventory))
        p = subprocess.Popen([PF9_EXPRESS,flags,'-b','-c',express_config,'-v',express_inventory,target_inventory],stdout=subprocess.PIPE,stderr=subprocess.PIPE)

    if user_input == 'y':
        sys.stdout.write("----------------------------------- Start Log -----------------------------------\n")
        tail_log(p)
    else:
        wait_for_job(p)


def run_express(du, host_entries):
    sys.stdout.write("\nPF9-Express Inventory (region type = {})\n".format(du['du_type']))
    if du['du_type'] == "Kubernetes":
        express_inventories = [
            'k8s_master',
            'k8s_worker'
        ]
    elif du['du_type'] == "KVM":
        express_inventories = [
            'all',
            'hypervisors',
            'glance',
            'cinder',
            'designate'
        ]
    else:
        express_inventories = [
            'all',
            'hypervisors',
            'glance',
            'cinder',
            'designate',
            'k8s_master',
            'k8s_worker'
        ]

    cnt = 1
    allowed_values = ['q']
    for inventory in express_inventories:
        sys.stdout.write("    {}. {}\n".format(cnt,inventory))
        allowed_values.append(str(cnt))
        cnt += 1
    user_input = read_kbd("\nSelect Inventory (to run PF9-Express against)", allowed_values, '', True, True)
    if user_input == "q":
        return()
    idx = int(user_input) - 1
    target_inventory = express_inventories[idx]

    sys.stdout.write("\nPF9-Express Role Assignment\n")
    sys.stdout.write("    1. Install Hostagent\n")
    sys.stdout.write("    2. Install Hostagent and Assign Roles\n")
    assign_roles = read_kbd("\nRole Assignment", ['q','1','2'], '1', True, True)
    if assign_roles == "q":
        return()
    else:
        if int(assign_roles) == 2:
            role_flag = 1
        else:
            role_flag = 0

    sys.stdout.write("\nConfiguring PF9-Express\n")
    express_config = build_express_config(du)
    if express_config:
        express_inventory = build_express_inventory(du, host_entries)
        if express_inventory:
            sys.stdout.write("\nRunning PF9-Express\n")
            flag_installed = install_express(du)
            if flag_installed == True:
                invoke_express(express_config, express_inventory, target_inventory, role_flag)


def import_region(region_json):
    sys.stdout.write("\nImporting Region\n")
    sys.stdout.write("--> specification file: {}\n".format(region_json))


def dump_text_file(target_file):
    BAR = "======================================================================================================"
    try:
        target_fh = open(target_file,mode='r')
        sys.stdout.write('\n========== {0:^80} ==========\n'.format(target_file))
        sys.stdout.write(target_fh.read())
        sys.stdout.write('{}\n'.format(BAR))
        target_fh.close()
    except:
        sys.stdout.write("ERROR: failed to open file: {}".format(target_file))


def view_log(log_files):
    cnt = 1
    allowed_values = ['q']
    for log_file in log_files:
        sys.stdout.write("{}. {}\n".format(cnt,log_file))
        allowed_values.append(str(cnt))
        cnt += 1
    user_input = read_kbd("Select Log", allowed_values, '', True, True)
    if user_input != "q":
        idx = int(user_input) - 1
        target_log = log_files[idx]
        target_log_path = "{}/{}".format(EXPRESS_LOG_DIR,target_log)
        dump_text_file(target_log_path)


def get_logs():
    log_files = []
    if not os.path.isdir(EXPRESS_LOG_DIR):
        return(log_files)

    for r, d, f in os.walk(EXPRESS_LOG_DIR):
        for file in f:
            if file == ".keep":
                continue
            log_files.append(file)

    return(log_files)


def view_inventory(du, host_entries):
    express_inventory = build_express_inventory(du, host_entries)
    if express_inventory:
        dump_text_file(express_inventory)
    else:
        sys.stdout.write("ERROR: failed to build inventory file: {}".format(express_inventory))


def view_config(du):
    express_config = build_express_config(du)
    if express_config:
        dump_text_file(express_config)
    else:
        sys.stdout.write("ERROR: failed to build configuration file: {}".format(express_config))


def dump_database(db_file):
    if os.path.isfile(db_file):
        with open(db_file) as json_file:
            db_json = json.load(json_file)
        print(db_json)

def run_cmd(cmd):
    cmd_stdout = ""
    tmpfile = "/tmp/pf9.{}.tmp".format(os.getppid())
    cmd_exitcode = os.system("{} > {} 2>&1".format(cmd,tmpfile))

    # read output of command
    if os.path.isfile(tmpfile):
        try:
            fh_tmpfile = open(tmpfile, 'r')
            cmd_stdout = fh_tmpfile.readlines()
        except:
            None

    os.remove(tmpfile)
    return cmd_exitcode, cmd_stdout


def display_menu1():
    sys.stdout.write("\n*****************************************\n")
    sys.stdout.write("**         Maintenance Menu            **\n")
    sys.stdout.write("*****************************************\n")
    sys.stdout.write("1. Delete Region\n")
    sys.stdout.write("2. Delete Host\n")
    sys.stdout.write("3. Display Region Database\n")
    sys.stdout.write("4. Display Host Database\n")
    sys.stdout.write("5. View Configuration File\n")
    sys.stdout.write("6. View Inventory File\n")
    sys.stdout.write("7. View Logs\n")
    sys.stdout.write("*****************************************\n")


def display_menu0():
    sys.stdout.write("*****************************************\n")
    sys.stdout.write("**          Platform9 Wizard           **\n")
    sys.stdout.write("**              Main Menu              **\n")
    sys.stdout.write("*****************************************\n")
    sys.stdout.write("1. Add/Update Regions\n")
    sys.stdout.write("2. Add/Update Hosts\n")
    sys.stdout.write("3. Add/Update Clusters\n")
    sys.stdout.write("4. Show Region\n")
    sys.stdout.write("5. Attach Host(s) to Region\n")
    sys.stdout.write("6. Maintenance\n")
    sys.stdout.write("*****************************************\n")


def menu_level1():
    user_input = ""
    while not user_input in ['q','Q']:
        display_menu1()
        user_input = read_kbd("Enter Selection", [], '', True, True)
        if user_input == '1':
            selected_du = select_du()
            if selected_du:
                if selected_du != "q":
                    delete_du(selected_du)
        elif user_input == '2':
            sys.stdout.write("\nNot Implemented\n")
        elif user_input == '3':
            dump_database(CONFIG_FILE)
        elif user_input == '4':
            dump_database(HOST_FILE)
        elif user_input == '5':
            selected_du = select_du()
            if selected_du:
                if selected_du != "q":
                    new_host = view_config(selected_du)
        elif user_input == '6':
            selected_du = select_du()
            if selected_du:
                if selected_du != "q":
                    host_entries = get_hosts(selected_du['url'])
                    new_host = view_inventory(selected_du, host_entries)
        elif user_input == '7':
            log_files = get_logs()
            if len(log_files) == 0:
                sys.stdout.write("\nNo Logs Found")
            else:
                view_log(log_files)
        elif user_input in ['q','Q']:
            None
        else:
            sys.stdout.write("ERROR: Invalid Selection (enter 'q' to quit)\n")
        sys.stdout.write("\n")


def menu_level0():
    user_input = ""
    while not user_input in ['q','Q']:
        display_menu0()
        user_input = read_kbd("Enter Selection", [], '', True, True)
        if user_input == '1':
            selected_du = add_edit_du()
            if selected_du != None:
                if selected_du == "define-new-du":
                    target_du = None
                else:
                    target_du = selected_du
                new_du_list = add_region(target_du)
                report_du_info(new_du_list)
        elif user_input == '2':
            sys.stdout.write("\nSelect Region to add Host to:")
            selected_du = select_du()
            if selected_du:
                if selected_du != "q":
                    new_host = add_host(selected_du)
        elif user_input == '3':
            sys.stdout.write("\nSelect Region to add Cluster to:")
            selected_du = select_du()
            if selected_du:
                if selected_du != "q":
                    new_cluster = add_cluster(selected_du)
        elif user_input == '4':
            selected_du = select_du()
            if selected_du:
                if selected_du != "q":
                    du_entries = get_configs(selected_du['url'])
                    report_du_info(du_entries)
                    host_entries = get_hosts(selected_du['url'])
                    report_host_info(host_entries)
                    if selected_du['du_type'] in ['Kubernetes','KVM/Kubernetes']:
                        cluster_entries = get_clusters(selected_du['url'])
                        report_cluster_info(cluster_entries)
        elif user_input == '5':
            sys.stdout.write("\nSelect Region to Run PF9-Express against:")
            selected_du = select_du()
            if selected_du:
                if selected_du != "q":
                    host_entries = get_hosts(selected_du['url'])
                    run_express(selected_du, host_entries)
        elif user_input == '6':
            menu_level1()
        elif user_input in ['q','Q']:
            None
        else:
            sys.stdout.write("ERROR: Invalid Selection (enter 'q' to quit)\n")

        if user_input != '7':
            sys.stdout.write("\n")


## main
args = _parse_args()

# globals
HOME_DIR = expanduser("~")
CONFIG_DIR = "{}/.pf9-wizard".format(HOME_DIR)
CONFIG_FILE = "{}/du.conf".format(CONFIG_DIR)
HOST_FILE = "{}/hosts.conf".format(CONFIG_DIR)
CLUSTER_FILE = "{}/clusters.conf".format(CONFIG_DIR)
EXPRESS_REPO = "https://github.com/platform9/express.git"
EXPRESS_INSTALL_DIR = "{}/.pf9-wizard/pf9-express".format(HOME_DIR)
EXPRESS_LOG_DIR = "{}/.pf9-wizard/pf9-express/log".format(HOME_DIR)
PF9_EXPRESS = "{}/.pf9-wizard/pf9-express/pf9-express".format(HOME_DIR)
MAX_WIDTH = 160

# perform initialization (if invoked with '--init')
if args.init:
    sys.stdout.write("INFO: initializing configuration\n")
    if os.path.isfile(HOST_FILE):
        os.remove(HOST_FILE)
    if os.path.isfile(CONFIG_FILE):
        os.remove(CONFIG_FILE)
    if os.path.isfile(CLUSTER_FILE):
        os.remove(CLUSTER_FILE)

# perform functions from commandline
if args.region:
    import_region(args.region)

# main menu loop
menu_level0()

# exit cleanly
sys.exit(0)
