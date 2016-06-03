# autodeploy
Deployment automation efforts for PF9 pre-reqs, host agent, and authorization.

## Instructions

After cloning the repo you'll need to create the following files.

### group_vars/all.yml

    ssh_user: root
    os_region: <OS region>
    os_username: <username>
    os_password: <password>
    os_tenant: <tenant name>
    du_url: <DU_UR>

### inventory/hypervisors

    [hypervisors]
    <fqdn> ansible_host=<ip>

## Example Playbook

    - hosts: hypervisors
      roles:
        - neutron-prerequisites
        - pf9-hostagent

## License
Commerical
