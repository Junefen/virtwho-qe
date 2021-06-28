import json
import os
import re
import string
import time
# import sys
# curPath = os.path.abspath(os.path.dirname(__file__))
# rootPath = os.path.split(curPath)[0]
# sys.path.append(os.path.split(rootPath)[0])
from random import random
from virtwho import logger, FailException
from virtwho.settings import config
from virtwho.ssh import SSHConnect


def rhel_version(ssh):
    ret, output = ssh.runcmd('cat /etc/redhat-release')
    if ret == 0 and output:
        m = re.search(r'(?<=release )\d', output)
        rhel_ver = m.group(0)
        return str(rhel_ver)
    raise FailException(f'Failed to get rhel release')


def compose_url(compose_id):
    base_url = config.repo.rhel_base
    repo_base = ''
    repo_extra = ''
    if 'updates' in compose_id:
        if 'RHEL-8' in compose_id:
            repo_base = (f'{base_url}/rhel-8/rel-eng/updates/RHEL-8/'
                         f'{compose_id}/compose/BaseOS/x86_64/os')
            repo_extra = (f'{base_url}/rhel-8/rel-eng/updates/RHEL-8/'
                          f'{compose_id}/compose/AppStream/x86_64/os')
        elif 'RHEL-7' in compose_id:
            repo_base = (f'{base_url}/rhel-7/rel-eng/updates/RHEL-7/'
                         f'{compose_id}/compose/Server/x86_64/os')
            repo_extra = (f'{base_url}/rhel-7/rel-eng/updates/RHEL-7/'
                          f'{compose_id}/compose/Server-optional/x86_64/os')
    elif '.n' in compose_id:
        if 'RHEL-8' in compose_id:
            repo_base = (f'{base_url}/rhel-8/nightly/RHEL-8/'
                         f'{compose_id}/compose/BaseOS/x86_64/os')
            repo_extra = (f'{base_url}/rhel-8/nightly/RHEL-8/'
                          f'{compose_id}/compose/AppStream/x86_64/os')
        elif 'RHEL-7' in compose_id:
            repo_base = (f'{base_url}/rhel-7/nightly/RHEL-7/'
                         f'{compose_id}/compose/Server/x86_64/os')
            repo_extra = (f'{base_url}/rhel-7/nightly/RHEL-7/'
                          f'{compose_id}/compose/Server-optional/x86_64/os')
    elif '.d' in compose_id:
        if 'RHEL-9' in compose_id:
            repo_base = (f'{base_url}/rhel-9/development/RHEL-9-Beta/'
                         f'{compose_id}/compose/BaseOS/x86_64/os')
            repo_extra = (f'{base_url}/rhel-9/development/RHEL-9-Beta/'
                          f'{compose_id}/compose/AppStream/x86_64/os')
        elif 'RHEL-8' in compose_id:
            repo_base = (f'{base_url}/rhel-8/development/RHEL-8/'
                         f'{compose_id}/compose/BaseOS/x86_64/os')
            repo_extra = (f'{base_url}/rhel-8/development/RHEL-8/'
                          f'{compose_id}/compose/AppStream/x86_64/os')
    else:
        if 'RHEL-9' in compose_id:
            repo_base = (f'{base_url}/rhel-9/composes/RHEL-9/'
                         f'{compose_id}/compose/BaseOS/x86_64/os')
            repo_extra = (f'{base_url}/rhel-9/composes/RHEL-9/'
                          f'{compose_id}/compose/AppStream/x86_64/os')
        elif 'RHEL-8' in compose_id:
            repo_base = (f'{base_url}/rhel-8/rel-eng/RHEL-8/'
                         f'{compose_id}/compose/BaseOS/x86_64/os')
            repo_extra = (f'{base_url}/rhel-8/rel-eng/RHEL-8/'
                          f'{compose_id}/compose/AppStream/x86_64/os')
        elif 'RHEL-7' in compose_id:
            repo_base = (f'{base_url}/rhel-7/rel-eng/RHEL-7/'
                         f'{compose_id}/compose/Server/x86_64/os')
            repo_extra = (f'{base_url}/rhel-7/rel-eng/RHEL-7/'
                          f'{compose_id}/compose/Server-optional/x86_64/os')
    return repo_base, repo_extra


def compose_repo(ssh, compose_id, repo_file):
    repo_base, repo_extra = compose_url(compose_id)
    cmd = (f'cat <<EOF > {repo_file}\n'
           f'[{compose_id}]\n'
           f'name={compose_id}\n'
           f'baseurl={repo_base}\n'
           f'enabled=1\n'
           f'gpgcheck=0\n\n'
           f'[{compose_id}-optional]\n'
           f'name={compose_id}-optional\n'
           f'baseurl={repo_extra}\n'
           f'enabled=1\n'
           f'gpgcheck=0\n'
           f'EOF')
    ssh.runcmd(cmd)


def virtwho_install(ssh, resource, gating_msg=None):
    rhel_ver = rhel_version(ssh)
    cmd = ('rm -rf /var/lib/rpm/__db*;'
           'mv /var/lib/rpm /var/lib/rpm.old;'
           'rpm --initdb;'
           'rm -rf /var/lib/rpm;'
           'mv /var/lib/rpm.old /var/lib/rpm;'
           'rm -rf /var/lib/yum/history/*.sqlite;'
           'rpm -v --rebuilddb')
    if rhel_ver == '6':
        cmd = 'dbus-uuidgen > /var/lib/dbus/machine-id'
    if rhel_ver == '8':
        cmd = 'localectl set-locale en_US.utf8; source /etc/profile.d/lang.sh'
    ssh.runcmd(cmd)
    if resource == 'gating' and gating_msg:
        env = gating_msg_parser(gating_msg)
        pkg_url = env['pkg_url']
        virtwho_install_by_url(ssh, pkg_url)
    else:
        ssh.runcmd('yum remove -y virt-who;'
                   'yum install -y virt-who')
    _, output = ssh.runcmd('rpm -qa virt-who')
    if 'virt-who' not in output:
        raise FailException('Failed to install virt-who package')
    logger.info(f'Succeeded to install {output.strip()}')


def virtwho_install_by_url(ssh, url):
    if not url_validation(url):
        raise FailException(f'package {url} is not available')
    ssh.runcmd('rm -rf /var/cache/yum/;'
               'yum clean all;'
               'yum remove -y virt-who')
    ssh.runcmd(f'yum localinstall -y {url}')


# def epel_packages_install(ssh):
#     epel_repo(ssh)
#     ssh.runcmd('yum clean all;'
#                'yum install -y expect tcl wget nmap')
#
#
# def epel_repo(ssh):
#     rhel_ver = rhel_version(ssh)
#     url_base = config.repo.epel
#     url = ''
#     if rhel_ver == '6':
#         url = f'{url_base}/6/x86_64/'
#     if rhel_ver == '7':
#         url = f'{0}/7/x86_64/'.format(url_base)
#     if rhel_ver == '8':
#         url = f'{url_base}/8/Everything/x86_64/'
#     cmd = (f'cat <<EOF > /etc/yum.repos.d/epel.repo\n'
#            f'[rhel-epel]\n'
#            f'name=rhel-epel\n'
#            f'baseurl={url}\n'
#            f'enabled=1\n'
#            f'gpgcheck=0\n'
#            f'EOF')


def url_validation(url):
    output = os.popen(f"if ( curl -o/dev/null -sfI '{url}' );"
                      f"then echo 'true';"
                      f"else echo 'false';"
                      f"fi").read()
    if output.strip() == 'true':
        return True
    raise FailException(f'The url:{url} is not available')


def gating_msg_parser(msg):
    msg = json.loads(msg)
    if 'info' in msg.keys():
        build_id = msg['info']['build_id']
        task_id = msg['info']['task_id']
    else:
        build_id = re.findall(r'"build_id":(.*?),', msg)[-1].strip()
        task_id = re.findall(r'"task_id":(.*?),', msg)[-1].strip()
    brew_build_url = f'{config.repo.brew}/brew/buildinfo?buildID={build_id}'
    output = os.popen(f'curl -k -s -i {brew_build_url}').read()
    pkg_url = re.findall(r'<a href="http://(.*?).noarch.rpm">download</a>',
                         output)[-1]
    if not pkg_url:
        raise FailException('no package url found')
    items = pkg_url.split('/')
    rhel_release = items[3]
    base_url = config.repo.rhel_base
    url = ''
    if 'rhel-9' in rhel_release:
        url = (f'{base_url}/rhel-9/nightly/RHEL-9-Beta/'
               f'latest-RHEL-9.0.0/COMPOSE_ID')
    if 'rhel-8' in rhel_release:
        url = (f'{base_url}/rhel-8/nightly/RHEL-8/'
               f'latest-RHEL-8.5/COMPOSE_ID')
    if 'rhel-7' in rhel_release:
        url = (f'{base_url}/rhel-7/rel-eng/RHEL-7/'
               f'latest-RHEL-7/COMPOSE_ID')
    rhel_compose = os.popen(f'curl -s -k -L {url}').read().strip()
    if not rhel_compose:
        raise FailException('no rhel compose found')
    env = dict()
    env['build_id'] = build_id
    env['task_id'] = task_id
    env['pkg_url'] = 'http://' + pkg_url + '.noarch.rpm'
    env['pkg_name'] = items[5]
    env['pkg_version'] = items[6]
    env['pkg_release'] = items[7]
    env['pkg_arch'] = items[8]
    env['pkg_nvr'] = items[9]
    env['rhel_release'] = rhel_release
    env['rhel_compose'] = rhel_compose
    return env


def get_exported_param(name):
    value = os.getenv(name)
    if value is None or value == '':
        value = None
    return value


def system_init(ssh, key):
    if ssh_connection(ssh):
        host_ip = ip_get(ssh)
        host_name = hostname_get(ssh)
        if (
                'localhost' in host_name
                or 'unused' in host_name
                or 'openshift' in host_name
                or host_name is None
        ):
            random_str = ''.join(
                random.sample(string.ascii_letters + string.digits, 8)
            )
            host_name = f'{key}-{random_str}.redhat.com'
        hostname_set(ssh, host_name)
        etc_hosts_set(ssh, host_ip, host_name)
        firewall_stop(ssh)
        selinux_disable(ssh)
        logger.info(f'Finished to init system {host_name}')


def ssh_connection(ssh):
    for i in range(60):
        ret, output = ssh.runcmd('rpm -qa filesystem')
        if ret == 0 and "filesystem" in output:
            logger.info('Succeeded to connect host by ssh')
            return True
        logger.info('Failed to connect host by ssh, try again after 60s...')
        time.sleep(60)
    logger.error(f'Failed to connect host by ssh after 60 times trying.')
    return False


def ip_get(ssh):
    cmd = "ip route get 8.8.8.8 | awk '/src/ { print $7 }'"
    ret, output = ssh.runcmd(cmd)
    if ret == 0 and output is not None:
        return output.strip()
    raise FailException(f'Failed to get ip address.')


def hostname_get(ssh):
    ret, output = ssh.runcmd('hostname')
    if ret == 0 and output:
        return output.strip()
    raise FailException('Failed to get hostname')


def hostname_set(ssh, hostname):
    ret1, _ = ssh.runcmd(f'hostnamectl set-hostname {hostname}')
    rhel_ver = rhel_version(ssh)
    cmd = (f"if [ -f /etc/hostname ];"
           f"then sed -i -e '/localhost/d' -e '/{hostname}/d' /etc/hostname;"
           f"echo {hostname} >> /etc/hostname; fi")
    if rhel_ver == '6':
        cmd = (f"sed -i '/HOSTNAME=/d' /etc/sysconfig/network;"
               f"echo 'HOSTNAME={hostname}' >> /etc/sysconfig/network")
    ret2, _ = ssh.runcmd(cmd)
    if ret1 != 0 or ret2 != 0:
        raise FailException('Failed to set hostname')


def etc_hosts_set(ssh, ip, hostname):
    ret, _ = ssh.runcmd(f"sed -i '/localhost/!d' /etc/hosts;"
                        f"echo '{ip} {hostname}' >> /etc/hosts")
    if ret != 0:
        raise FailException(f'Failed to set /etc/hosts for {ip}')


def pkg_check(self, ssh, package):
    cmd = "rpm -qa {0}".format(package)
    ret, output = self.runcmd(cmd, ssh)
    if ret == 0 and output is not None and output != "":
        pkg = output.strip() + ".rpm"
        return pkg
    else:
        return False


def firewall_stop(ssh):
    rhel_ver = rhel_version(ssh)
    cmd = 'systemctl stop firewalld.service;' \
          'systemctl disable firewalld.service'
    if rhel_ver == '6':
        cmd = 'service iptables stop; chkconfig iptables off'
    ret, _ = ssh.runcmd(cmd)
    if ret == 0:
        logger.info('Succeeded to stop firewall')
        return True
    raise FailException('Failed to stop firewall')


def selinux_disable(ssh):
    ret, _ = ssh.runcmd("setenforce 0; sed -i -e "
                        "'s/SELINUX=.*/SELINUX=disabled/g' /etc/selinux/config")
    if ret == 0:
        logger.info('Succeeded to disable selinux')
        return True
    raise FailException('Failed to disable selinux')


def rhel_repos(rhel_ver):
    repos = (f'rhel-{rhel_ver}-server-rpms,'
             f'rhel-{rhel_ver}-server-optional-rpms,'
             f'rhel-{rhel_ver}-server-extras-rpms,'
             f'rhel-server-rhscl-{rhel_ver}-rpms')
    return repos


def no_passwd_access_libvirt(ssh):
    libvirt_server = config.libvirt.server
    libvirt_username = config.libvirt.username
    libvirt_password = config.libvirt.password
    if libvirt_server and libvirt_username and libvirt_password:
        ssh_libvirt = SSHConnect(host=libvirt_server,
                                 user=libvirt_username,
                                 pwd=libvirt_password)
        ssh.runcmd('echo -e "\n" | ssh-keygen -N "" &> /dev/null')
        ret, output = ssh.runcmd('cat ~/.ssh/id_rsa.pub')
        if ret != 0 or not output:
            raise FailException('Failed to create ssh key')
        ssh_libvirt.runcmd(f'mkdir ~/.ssh/;'
                           f'echo "{output}" >> ~/.ssh/authorized_keys')
        ssh.runcmd(f'ssh-keyscan -p 22 {libvirt_server} >> ~/.ssh/known_hosts')
        logger.info('Succeeded to copy sshkey to remote libvirt')
