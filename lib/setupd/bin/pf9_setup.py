#!/opt/pf9/setupd/bin/python2
# vim: set et ts=4 sw=4

# Copyright 2017 Platform9 Systems

NGINX_CONF_SETUP = '/etc/nginx/nginx.conf.setup'
ANSIBLE_STACK_DIR = '/var/lib/ansible-stack'
ERROR_FILE = '/opt/pf9/www/fail-landing/error.txt'

import sys
import os
import errno
import re
import MySQLdb
import logging
import subprocess
import shutil
import uuid
import tempfile
from setupd.fts import create_and_verify_db_connection, \
                       ensure_metadata_schema, configure_du
from setupd.config import Configuration, PasswordData
from setupd.common import get_release_version, \
                          get_state_data, set_state_data, \
                          STATE_FILE
from setupd.util import slurp_file
import argparse
from getpass import getpass

LOG = logging.getLogger(__name__)

def print_intro_banner():
    # TODO: fancy ascii stuff?
    print '***** PLATFORM9 *****'


def add_hosts_entry(ipaddr, hostnames):
    """
    Adds static DNS names to /etc/hosts. This is needed for local configuration
    to complete.
    """
    host_data = []
    if type(hostnames) in (str,unicode):
        hostnames = [hostnames]
    with open('/etc/hosts', 'r') as f:
        host_data = f.readlines()
    host_line = '%s %s' % (ipaddr, ' '.join(hostnames))
    if host_line in host_data:
        LOG.info('Already has a hosts entry, skipping...')
        return
    host_data.append(host_line)
    tmpf = tempfile.NamedTemporaryFile(delete=False)
    tmpf.write('\n'.join(host_data))
    tmpf.close()
    shutil.move(tmpf.name, '/etc/hosts')


def enter_configure_phase(db, config_data, state_data, log_dir, initial_password):
    """
    Apply configuration to state.ini.
    Stage out and start an ansible run.
    """
    config_data.sync_certificates()
    config_data.sync_passwords()
    config_data.phase = 'CONFIGURING'
    config_data.save(db)
    add_hosts_entry('127.0.0.1', [config_data.fqdn])
    configure_du(config_data, initial_password, db, log_dir, state_data=state_data)


def parse_args():
    ap = argparse.ArgumentParser(sys.argv[0],
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument('--log-dir', required=False, dest='log_dir',
                    metavar='dir', default='/var/log',
                    help='Log directory')
    ap.add_argument('--log-level', required=False, dest='log_level',
                    metavar='level', default='INFO',
                    help='Log level (CRITICAL, ERROR, WARNING, INFO, DEBUG)')
    ap.add_argument('--fullname', required=True, dest='fullname',
                    metavar='customer_full_name',
                    help='Full customer name')
    ap.add_argument('--shortname', required=True, dest='shortname',
                    metavar='customer_shortname',
                    help='Customer shortname')
    ap.add_argument('--fqdn', required=True, dest='fqdn',
                    help='Fully Qualified Domain Name of instance')
    ap.add_argument('--admin-user', required=True, dest='admin_user',
                    help='Email address of first admin')
    ap.add_argument('--admin-password', required=False, dest='admin_password',
                    help='Initial password of first admin')
    ap.add_argument('--admin-password-file', required=False, dest='admin_password_file',
                    help='Path to file containing admin password')
    ap.add_argument('--web-cert', required=False, dest='web_cert', metavar='cert',
                    help='Path to https certificate')
    ap.add_argument('--web-key', required=False, dest='web_key', metavar='key',
                    help='Path to https private key')
    ap.add_argument('--consul-url', required=False, default='http://localhost:8500',
                    dest='consul_url', metavar='url',
                    help='Consul URL')
    ap.add_argument('--db-host', required=False, default='127.0.0.1',
                    dest='db_host', metavar='hostname',
                    help='Database hostname')
    ap.add_argument('--db-port', required=False, default=3306,
                    type=int, dest='db_port', metavar='port',
                    help='Database port')
    ap.add_argument('--db-user', required=False, default='root',
                    dest='db_user', metavar='user',
                    help='Database user')
    ap.add_argument('--db-password', required=False,
                    dest='db_password', metavar='password',
                    help='Database password')
    ap.add_argument('--db-password-file', required=False,
                    type=int, dest='db_password_file', metavar='file',
                    help='File to read database password from')
    ap.add_argument('--registry-url', required=False,
                    dest='registry_url', metavar='registry_url',
                    help='Amazon ECR Registry URL')
    ap.add_argument('--ecr-region', required=False, default='us-west-1',
                    dest='ecr_region', metavar='region_name',
                    help='AWS Region which the ECR Registry URL resides in')
    ap.add_argument('--aws-access-key', required=False,
                    dest='aws_access_key', metavar='access_key_id',
                    help='AWS Access Key ID')
    ap.add_argument('--aws-secret-key', required=False,
                    dest='aws_secret_key', metavar='secret_key',
                    help='AWS Secret Key')
    ap.add_argument('--aws-secret-key-file', required=False,
                    dest='aws_secret_key_file', metavar='secret_key_file',
                    help='Path to file containing AWS Secret Key')
    ap.add_argument('--registry-user', required=False,
                    dest='registry_user', metavar='user',
                    help='Registry login username')
    ap.add_argument('--registry-password', required=False,
                    dest='registry_password', metavar='password',
                    help='Registry login password')
    ap.add_argument('--registry-password-file', required=False,
                    dest='registry_password_file', metavar='password_file',
                    help='Path to file containing registry password')
    ap.add_argument('--image-tag', required=False, default='latest',
                    dest='image_tag', metavar='tag_name',
                    help='tag to fetch for all container images')
    ap.add_argument('--region', required=True,
                    dest='region', metavar='region_name',
                    help='Keystone Region Name')

    return ap.parse_args()


def resolve_state_from_cmdline(state_data, pargs):
    overrides = [
        'fullname',
        'shortname',
        'fqdn',
        'admin_user',
        'admin_password',
        'region',
        ['web_cert', 'web_key'],
        'registry_url', 'ecr_region',
        'aws_access_key', 'aws_secret_key',
        'registry_user', 'registry_password',
        'consul_url',
        'image_tag',
        'db_host',
        'db_port',
        'db_user',
        'db_password'
        ]
    for override_vars in overrides:
        if type(override_vars) == list:
            # Arguments that depend on each other to make sense.
            # If you specify, say, web cert, we require the key to go with it,
            # so check to make sure all combined params have been specified.
            missing_vars = []
            found_vars = []
            for var_name in override_vars:
                if getattr(pargs, var_name, None) is None:
                    missing_vars.append(var_name)
                else:
                    found_vars.append(var_name)
            if missing_vars and found_vars:
                print >>sys.stderr, 'Expected combination of %s. only got %s.' % \
                                    (','.join(override_vars), ','.join(missing_vars))
                sys.exit(2)
            for var_name in override_vars:
                state_data[var_name] = getattr(pargs, var_name)
        else:
            val = getattr(pargs, override_vars)
            if val or override_vars not in state_data:
                state_data[override_vars] = val

    if pargs.db_password_file:
        with open(pargs.db_password_file) as f:
            state_data['db_password'] = f.read()


VALIDATION_REGEXES = [
    re.compile(r'[0-9]'),
    re.compile(r'[a-z]'),
    re.compile(r'[A-Z]')
]


def valid_password(passwd):
    if len(passwd) < 10:
        return False

    for pwd_rgx in VALIDATION_REGEXES:
        if not pwd_rgx.search(passwd):
            return False

    return True


def resolve_log_level(level_name):
    level_name = level_name.upper()
    if level_name not in ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']:
        raise Exception('Invalid log level: %s' % level_name)
    return getattr(logging, level_name)


def main():
    print_intro_banner()
    pargs = parse_args()

    try:
        os.makedirs(pargs.log_dir)
    except OSError as ex:
        if ex.errno != errno.EEXIST:
            raise

    logging.basicConfig(level=resolve_log_level(pargs.log_level))
    log_file = os.path.join(pargs.log_dir, 'pf9-setup.log')
    root_logger = logging.getLogger()
    root_logger.addHandler(logging.StreamHandler(sys.stdout))
    root_logger.addHandler(logging.FileHandler(log_file))

    # retrieve previously recorded data (most likely originating from cloud-init)
    state_data = get_state_data() or {}

    if state_data.get('machine_uuid', None):
        LOG.warn(
            'Machine configured prior? (UUID: %s)',
            state_data['machine_uuid'])

    resolve_state_from_cmdline(state_data, pargs)

    if pargs.admin_password_file:
        LOG.info('Retrieving admin password from %s', pargs.admin_password_file)
        state_data['admin_password'] = slurp_file(pargs.admin_password_file).strip()
    if pargs.registry_password_file:
        LOG.info('Retrieving registry password from %s', pargs.registry_password_file)
        state_data['registry_password'] = slurp_file(pargs.registry_password_file).strip()
    if pargs.aws_secret_key_file:
        LOG.info('Retrieving AWS secret key from %s', pargs.aws_secret_key_file)
        state_data['aws_secret_key'] = slurp_file(pargs.aws_secret_key_file).strip()
    LOG.debug(state_data)

    web_cert = web_key = None
    if state_data.get('web_cert', None):
        web_cert = slurp_file(state_data['web_cert'])
        web_key = slurp_file(state_data['web_key'])

    db_host = state_data.get('db_host', None)
    db_port = int(state_data.get('db_port', '3306'))
    db_user = state_data.get('db_user', None)
    db_passwd = state_data.get('db_password', None)

    if db_host is None or \
            db_port is None or \
            db_user is None or \
            db_passwd is None:
        LOG.info('Not enough information to test DB connection. entering setup')
        return 1

    try:
        db = create_and_verify_db_connection(
            db_host, db_port, db_user, db_passwd)
    except Exception as ex:
        LOG.exception(ex)
        LOG.info('DB credentials non-existent, invalid, or '
                 'do not have the right permissions.')
        return 1

    with db.cursor() as cursor:
        cursor.execute('CREATE DATABASE IF NOT EXISTS `pf9_metadata`')
    db.commit()
    db.select_db('pf9_metadata')
    ensure_metadata_schema(db)

    # This needs to be destroyed after FTS
    admin_password = state_data.get('admin_password', None)
    if not admin_password:
        if sys.stdin.isatty():
            LOG.info('No password given')
            admin_password = getpass('Please enter initial admin password: ')
            while not valid_password(admin_password):
                print 'Password not strong enough.'
                print '(needs at least 1 lowercase character, 1 uppercase, 1 digit, '
                print ' and to be at least 10 characters in length)'
                admin_password = getpass('Please enter initial admin password: ')
        else:
            LOG.info('No admin password set. Exiting.')
            return 1
    elif not valid_password(admin_password):
        LOG.info('Password set but not valid?')
        return 1

    state_fqdn = state_data.get('fqdn', None)
    state_uuid = state_data.get('uuid', None)
    configs = Configuration.load_all_from_db(db)
    if not configs:
        # No configurations available in the database, but
        # do we have what we need in state data to create one?
        LOG.info('No configurations present. Checking state data.')
        fullname = state_data.get('fullname', None)
        admin_user = state_data.get('admin_user', None)
        shortname = state_data.get('shortname', None)
        region = state_data.get('region', None)
        if state_fqdn and fullname and admin_user and \
                shortname and region:
            new_config = Configuration()
            new_config.customer.fullname = fullname
            new_config.customer.admin_user = admin_user
            new_config.customer.shortname = shortname
            new_config.fqdn = state_fqdn
            new_config.region = region
            new_config.release_version = get_release_version()
            new_config.save(db)
            new_config.sync_certificates()
            new_config.sync_passwords()
            new_config.save(db)
            configs.append(new_config)

    if len(configs) == 0:
        LOG.info('No configurations available. Exiting.')
        return 1

    selected_config = None
    if len(configs) > 1:
        if state_fqdn:
            # Pick the config that matches the provided fqdn.
            # If a machine uuid is provided and also a match, it gets top pick.
            for config_data in configs:
                if state_uuid and config_data.uuid == state_uuid:
                    LOG.info('Found exact match for %s (%s)',
                        state_fqdn, state_uuid)
                    selected_config = config_data
                elif not selected_config and config_data.fqdn == state_fqdn:
                    LOG.info('Found FQDN match for %s', state_fqdn)
                    selected_config = config_data
    else:
        selected_config = configs[0]
        if state_fqdn and selected_config.fqdn != state_fqdn:
            LOG.info('%s is in state data, %s is in the database', state_fqdn, selected_config.fqdn)
            LOG.info('Conflicting state information with single config in database.  Exiting.')
            return 1

    if not selected_config:
        LOG.info('Cannot determine configuration. Exiting.')
        return 1

    # plaster specified web certificate into current configuration. it takes priority over
    # what we previously had if explicitly specified.
    if web_cert and web_key:
        web_cert_model = selected_config.certificates[selected_config.cert_version]['web']
        web_cert_model.cert_pem = web_cert
        web_cert_model.private_key_pem = web_key
        web_cert_model.save(db)

    enter_configure_phase(db, selected_config, state_data, pargs.log_dir, admin_password)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as ex:
        LOG.exception(ex)
        LOG.critical('Really bad things happened: %s', str(ex))
        sys.exit(1)
