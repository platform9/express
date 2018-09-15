#!/usr/bin/env python

from setupd_samples.utils.pf9_utils import login, create_cluster
import argparse, sys, logging
import urllib3
from setupd_samples.utils import setup_logs
urllib3.disable_warnings()
LOG = logging.getLogger(__name__)

def parse_args():
    ap = argparse.ArgumentParser(sys.argv[0],
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument('--admin-user', required=True, dest='admin_user',
                    help='Email address of first admin')
    ap.add_argument('--admin-password', required=True, dest='admin_password',
                    help='Initial password of first admin')
    ap.add_argument('--master-ip', required=True, dest='master_ip')
    return ap.parse_args()

def mgmt_cluster_create(ctrl_ip, admin_user, admin_password, master_ip, cluster_name='defaultCluster'):
    print "Creating cluster specification"
    auth = login(ctrl_ip, admin_user, admin_password, 'service')
    print 'Login succeded, creating cluster'
    create_cluster(ctrl_ip, master_ip, auth, cluster_name)

def main():
    args = parse_args()
    mgmt_cluster_create(args.admin_user, args.admin_password, args.master_ip)

if __name__ == '__main__':
    try:
        setup_logs('/var/log/pf9-mgmt-setup.log')
        sys.exit(main())
        print "Default cluster done"
    except Exception as ex:
        print "cluster creation failed"
        LOG.exception(ex)
        LOG.error('Really bad things happened: %s', str(ex))
        sys.exit(1)
