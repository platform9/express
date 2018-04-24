#!/usr/bin/python

import getpass
import json
import optparse
import sys

if sys.version_info.major == 2:
    import httplib
    import urlparse
elif sys.version_info.major == 3:
    from http import client as httplib
    from urllib import parse as urlparse


def do_request(action, host, relative_url, headers, body):
    conn = httplib.HTTPSConnection(host)
    body_json = json.JSONEncoder().encode(body)
    conn.request(action, relative_url, body_json, headers)
    response = conn.getresponse()
    return conn, response


def download_report(bytes_so_far, total_size, installer_name):
    percent = float(bytes_so_far) / total_size
    percent = round(percent * 100, 2)
    sys.stdout.write("{0}: Downloaded {1} of {2} bytes {3:.2f}%\r".format(
        installer_name, bytes_so_far, total_size, percent))

    if bytes_so_far >= total_size:
        sys.stdout.write('\n')


def download_installer(url, token, cookie, installer_name):
    headers = {"X-Auth-Token": token, "cookie": cookie}
    body = ""

    _, net_location, path, _, _ = urlparse.urlsplit(url)
    conn, response = do_request("GET", net_location, path, headers, body)

    if response.status != 200:
        print("{0}: {1}".format(response.status, response.reason))
        exit(1)

    total_size = int(response.getheader('Content-Length').strip())
    bytes_read = 0

    # writes the file in the current working directory
    installer_file = open(installer_name, 'wb')

    while True:
        body = response.read(512 * 1024)
        bytes_read += len(body)

        if not body:
            break

        installer_file.write(body)
        download_report(bytes_read, total_size, installer_name)

    installer_file.close()
    conn.close()


def get_token_v3(host, username, password, tenant):
    headers = {"Content-Type": "application/json"}
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
                    "name": tenant,
                    "domain": {"id": "default"}
                }
            }
        }
    }
    conn, response = do_request("POST", host,
                                "/keystone/v3/auth/tokens?nocatalog",
                                headers, body)

    if response.status not in (200, 201):
        print("{0}: {1}".format(response.status, response.reason))
        exit(1)

    token = response.getheader('X-Subject-Token')
    conn.close()
    return token


def get_package_info_from_token(host, token, region):

    out = {}

    headers = {
        "Content-Type": "application/json",
        "X-Auth-Token": token
    }

    conn, response = do_request("GET", host,
                                "/keystone/v3/services?type=regionInfo",
                                headers, {})
    if response.status not in (200, 201):
        print("{0}: {1}".format(response.status, response.reason))
        exit(1)

    response_text = response.read().decode('utf-8')
    response_body = json.loads(response_text)
    service_id = response_body['services'][0]['id']
    conn.close()

    conn, response = do_request(
        "GET", host,
        "/keystone/v3/endpoints?service_id={0}".format(service_id), headers,
        {})
    if response.status not in (200, 201):
        print("{0}: {1}".format(response.status, response.reason))
        exit(1)

    response_text = response.read().decode('utf-8')
    response_body = json.loads(response_text)
    for endpoint in response_body['endpoints']:
        if endpoint['region'] == region:
            if endpoint['interface'] == 'internal':
                internal_url = endpoint['url']
            elif endpoint['interface'] == 'public':
                public_url = endpoint['url']
    conn.close()

    _, net_location, path, _, _ = urlparse.urlsplit(public_url)
    conn, response = do_request("GET", net_location, path, headers, {})
    if response.status not in (200, 201):
        print("{0}: {1}".format(response.status, response.reason))
        exit(1)

    response_text = response.read().decode('utf-8')
    response_body = json.loads(response_text)
    cookie_url = response_body['links']['token2cookie']
    conn.close()

    _, net_location, path, _, _ = urlparse.urlsplit(cookie_url)
    conn, response = do_request("GET", net_location, path, headers, {})
    if response.status not in (200, 201, 204):
        print("{0}: {1}".format(response.status, response.reason))
        exit(1)

    cookie = response.getheader('set-cookie')
    conn.close()

    headers['cookie'] = cookie
    _, net_location, path, _, _ = urlparse.urlsplit(internal_url)
    conn, response = do_request("GET", net_location, path, headers, {})
    if response.status not in (200, 201):
        print("{0}: {1}".format(response.status, response.reason))
        exit(1)

    response_text = response.read().decode('utf-8')
    response_body = json.loads(response_text)
    deb_installer = response_body['links']['deb_install']
    rpm_installer = response_body['links']['rpm_install']
    conn.close()

    out = {
        'cookie': cookie,
        'internal_url': internal_url,
        'public_url': public_url,
        'deb_installer': deb_installer,
        'rpm_installer': rpm_installer
    }

    return out


def get_installer(options):
    token = get_token_v3(options.endpoint, options.user,
                         options.pw, options.tenant)

    info = get_package_info_from_token(options.endpoint, token, options.region)
    if options.platform == 'debian':
        package_url = info['deb_installer']
    elif options.platform == 'redhat':
        package_url = info['rpm_installer']

    installer_name = package_url.rsplit('/', 1)[1]
    download_installer(package_url, 'token', info['cookie'], installer_name)


def validate_password(options):
    if not options.pw:
        options.pw = getpass.getpass()


def main():
    parser = optparse.OptionParser(
        usage="%prog --account_endpoint <endpoint> "
        "--region <region> --user <user> [--password <password>]"
        " [--tenant <tenant>] --platform <redhat|debian>")
    parser.add_option(
        '--account_endpoint',
        dest="endpoint",
        action="store",
        help="Account endpoint for the customer. Example: acme.platform9.net")
    parser.add_option(
        '--region',
        dest="region",
        action="store",
        help="Region from where the installer needs to be downloaded")
    parser.add_option(
        '--user',
        dest="user",
        action="store",
        help="Platform9 user account to use to retrieve the installer")
    parser.add_option(
        '--password',
        dest="pw",
        action="store",
        default=None,
        help="User account password. Will be prompted, if not provided during "
        "script invocation")
    parser.add_option(
        '--tenant',
        dest="tenant",
        action="store",
        default="service", help="Tenant to use for the user account. Defaults "
        "to 'service' tenant")
    parser.add_option(
        '--platform',
        dest="platform",
        action="store",
        help="Installer platform. Allowed options are redhat or debian.",
        type='choice', choices=['redhat', 'debian'])

    options, _ = parser.parse_args()
    if not (options.endpoint and options.region and
            options.user and options.tenant):
        print("ERROR: Missing arguments")
        parser.print_usage()
        sys.exit(1)

    validate_password(options)

    get_installer(options)


if __name__ == "__main__":
    main()
