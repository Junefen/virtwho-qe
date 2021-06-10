import re
import string
import time
from random import random
from virtwho import logger, FailException


def rhel_version(ssh):
    ret, output = ssh.runcmd('cat /etc/redhat-release')
    if ret == 0 and output:
        m = re.search(r'(?<=release )\d', output)
        rhel_ver = m.group(0)
        return str(rhel_ver)
    raise FailException(f'Failed to get rhel release')


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
