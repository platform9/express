#!/usr/bin/env python

from setupd_samples.utils.pf9_utils import login,attach_master_node
from setupd_samples.utils import setup_logs
from setupd_samples.utils import command_exec
import argparse, sys
import requests, logging, subprocess, ConfigParser, time
from setupd_samples.utils.resmgr import wait_for_host_in_resmgr, authorize_host
import urllib3
urllib3.disable_warnings()
DOWNLOAD_FILE_NAME="/tmp/platform9-install-redhat.sh"

LOG = logging.getLogger(__name__)

def parse_args():
    ap = argparse.ArgumentParser(sys.argv[0],
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument('--mgmt-address', required=True, dest='mgmt_address',
                    help='Management IP address')
    ap.add_argument('--admin-user', required=True, dest='admin_user',
                    help='Email address of first admin')
    ap.add_argument('--admin-password', required=True, dest='admin_password',
                    help='Initial password of first admin')
    return ap.parse_args()

def _install_agent(du_host, user, password):
    command = "bash %s --insecure --no-proxy --ntpd --skip-os-check --controller=%s --username=%s --password=%s --project-name=service " % (DOWNLOAD_FILE_NAME, du_host, user, password)
    command_exec.call(command)
    LOG.info('Ran Platform9 agent')

def download_and_install_agent(du_host, user, password):
    url = "https://%s/clarity/platform9-install-redhat.sh" % du_host
    LOG.info('Downloading platform9-install from %s' % (du_host))

    response = requests.get(url, stream=True, verify=False)
    response.raise_for_status()

    handle = open(DOWNLOAD_FILE_NAME, "w")
    for chunk in response.iter_content(chunk_size=4096):
        if chunk:  # filter out keep-alive new chunks
            handle.write(chunk)
    handle.close()
    LOG.info('File downloaded %s' % DOWNLOAD_FILE_NAME)

    # Now install it
    return _install_agent(du_host, user, password)

def read_host_id():
    cfg_parser = ConfigParser.ConfigParser()
    cfg_parser.readfp(open('/etc/pf9/host_id.conf'))
    return cfg_parser.get('hostagent', 'host_id')

def configure_master(mgmt_address, admin_user, admin_password, cluster_name='defaultCluster'):
    print("Downloading agents from management node")
    download_and_install_agent(mgmt_address, admin_user, admin_password)
    auth = login(mgmt_address, admin_user, admin_password, 'service')
    host_id = read_host_id()
    print('Waiting for host to startup')
    wait_for_host_in_resmgr(mgmt_address, auth, host_id)
    print('Pre - Kubernetes setup')
    authorize_host(auth, mgmt_address, host_id, 'pf9-kube')
    print('Waiting for the node to be attached in Kubernetes')
    # wait additional 30 seconds for the authorization to complete
    time.sleep(120)
    attach_master_node(auth, mgmt_address, host_id, cluster_name)
    print('Done')

def attach_master(mgmt_ip, admin_user, admin_password, host_id, cluster_name='defaultCluster'):
    auth = login(mgmt_ip, admin_user, admin_password, 'service')
    attach_master_node(auth, mgmt_ip, host_id, cluster_name)
    print('attach_master() : Done')

def main():
    setup_logs('/var/log/pf9/master.log')
    args = parse_args()
    configure_master(args.mgmt_address, args.admin_user, args.admin_password)


if __name__ == '__main__':
    try:

        main()
        print("Master setup is done")
    except Exception as ex:
        print("master setup failed")
        LOG.exception(ex)
        LOG.error('Really bad things happened: %s', str(ex))
        sys.exit(1)
