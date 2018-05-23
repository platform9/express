#!/opt/pf9/setupd/bin/python2

import argparse, sys, json
import logging
from setupd_samples.utils import setup_logs
from setupd_samples.utils.qbert import Qbert
from setupd_samples.utils.pf9_utils import login
from prettytable import PrettyTable
import urllib3

urllib3.disable_warnings()

DOWNLOAD_FILE_NAME="/tmp/platform9-install-redhat.sh"

LOG = logging.getLogger(__name__)

def parse_args():
    ap = argparse.ArgumentParser(sys.argv[0],
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    ap.add_argument('--mgmt-ip', required=True, dest='mgmt_address',
                    help='Management IP address')
    ap.add_argument('--admin-user', required=True, dest='admin_user',
                    help='Email address of first admin')
    ap.add_argument('--admin-password', required=True, dest='admin_password',
                    help='Initial password of first admin')
    sp = ap.add_subparsers(dest='subparser')
    sp_list_cluster = sp.add_parser('list-clusters', help='List clusters')
    sp_get_kubeconfig = sp.add_parser('get-kubeconfig', help='Get Kubeconfig for cluster')
    sp_get_kubeconfig.add_argument('--name', required=True, dest='cluster_name')
    sp_list_nodes = sp.add_parser('list-nodes', help='List Nodes')

    return ap.parse_args()

def _print_list(header, rows):
    table = PrettyTable()
    table._set_field_names(header)
    for row in rows:
        table.add_row(row)
    print table

def _print_cluster_list(clusters):
    header = ["name", "services cidr", "master_ip", "status", "dns name"]
    rows = []
    for cluster_name, properties in clusters.iteritems():
        row = [
            cluster_name,
            properties['servicesCidr'],
            properties['masterIp'],
            properties['status'],
            properties['externalDnsName']

        ]
        rows.append(row)
    _print_list(header, rows)

def _print_node_list(nodes):
    header = ["name", "primary ip", "master", "cluster"]
    rows = []
    for node_name, properties in nodes.iteritems():
        row = [
            node_name,
            properties['primaryIp'],
            properties['isMaster'],
            properties['clusterName']

        ]
        rows.append(row)
    _print_list(header, rows)


def main():
    setup_logs('/var/log/pf9/qb.log')
    args = parse_args()
    token = login(args.mgmt_address, args.admin_user, args.admin_password, 'service')
    qbert = Qbert(token, 'https://%s/qbert/v1'%args.mgmt_address)
    if args.subparser == 'list-clusters':
        _print_cluster_list(qbert.list_clusters())
    elif args.subparser == 'get-kubeconfig':
        print qbert.get_kubeconfig(args.cluster_name, args.admin_user, args.admin_password)
    elif args.subparser == 'list-nodes':
        _print_node_list(qbert.list_nodes())



if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as ex:
        print ex
        LOG.exception(ex)
        LOG.critical('Really bad things happened: %s', str(ex))
        sys.exit(1)
