import time
import random
import string
import os
import sys

import argparse
curPath = os.path.abspath(os.path.dirname(__file__))
rootPath = os.path.split(curPath)[0]
sys.path.append(os.path.split(rootPath)[0])

from virtwho.settings import config
from virtwho import logger, FailException
from virtwho.ssh import SSHConnect
from virtwho.provision import base


def rhel_install_by_grub(args):
    """
    Deploy a rhel host by upgrading grub file, which is mainly for
    running virt-who in local mode. Please refer to the README for usage.
    :param args: rhel_compose, host, username, password, virtwho_resource, gating_msg
        rhel_compose: rhel compose id to be installed
        host: the hostname or ip of the existing rhel host
        username: the username of the existing host
        password: the password of the existing host
        virtwho_resource: compose or gating
        gating_msg: should be a json
    """
    compose_id = args.rhel_compose
    compose_repo_file = '/etc/yum.repos.d/compose.repo'
    host = args.host
    username = args.username
    password = args.password
    ssh = SSHConnect(host=host, user=username, pwd=password)

    nfs_server = config.nfs.server
    nfs_server_username = config.nfs.server_username
    nfs_server_password = config.nfs.server_password
    nfs_url = config.nfs.rhel_url
    nfs_mount = config.nfs.rhel_mount
    ssh_nfs = SSHConnect(host=nfs_server,
                         user=nfs_server_username,
                         pwd=nfs_server_password)

    random_str = ''.join(
        random.sample(string.ascii_letters + string.digits, 8)
    )
    ks_name = f'{random_str}.cfg'
    ks_url = f'{nfs_url}/{ks_name}'
    ks_path = f'{nfs_mount}/{ks_name}'
    repo_base, repo_extra = base.compose_url(compose_id)
    ks_file_create(ssh_nfs, ks_url, ks_path, password, repo_base, repo_extra)
    vmlinuz_url = f'{repo_base}/isolinux/vmlinuz'
    initrd_url = f'{repo_base}/isolinux/initrd.img'
    try:
        grub_update(ssh, ks_url, vmlinuz_url, initrd_url, repo_base)
        if base.ssh_connection(ssh):
            base.system_init(ssh, key='libvirt-local')
            base.compose_repo(ssh, compose_id, compose_repo_file)
            base_packages_install(ssh, compose_id)
            if args.virtwho_resource:
                base.virtwho_install(ssh=ssh,
                                     resource=args.virtwho_resource,
                                     gating_msg=args.gating_msg)
            base.no_passwd_access_libvirt(ssh)
        else:
            raise FailException(f'Failed to connect {host} by ssh')
    except Exception as e:
        logger.error(e)
    finally:
        ssh.runcmd(f'rm -rf {ks_path}')


def ks_file_create(ssh, ks_url, ks_path, password, repo_base, repo_extra):
    """

    :param ssh:
    :param ks_url:
    :param ks_path:
    :param password:
    :param repo_base:
    :param repo_extra:
    :return:
    """
    cmd = (f'cat <<EOF > {ks_path}\n'
           f'text\n'
           f'bootloader --location=mbr\n'
           f'lang en_US.UTF-8\n'
           f'keyboard us\n'
           f'network  --bootproto=dhcp --activate\n'
           f'rootpw --plaintext {password}\n'
           f'firewall --disabled\n'
           f'selinux --disabled\n'
           f'timezone Asia/Shanghai\n'
           f'zerombr\n'
           f'clearpart --all --initlabel\n'
           f'autopart\n'
           f'reboot\n'
           f'repo --name=base --baseurl={repo_base}\n'
           f'repo --name=extra --baseurl={repo_extra}\n'
           f'%packages --ignoremissing\n'
           f'@base\n'
           f'%end\n'
           f'%post\n'
           f'sed -i "s/#*PermitRootLogin.*/PermitRootLogin yes/g" /etc/ssh/sshd_config\n'
           f'sed -i "s@session\\s*required\\s*pam_loginuid.so@session optional pam_loginuid.so@g" /etc/pam.d/sshd\n'
           f'%end\n'
           f'EOF')
    ssh.runcmd(cmd)
    ret, output = ssh.runcmd(f'ls {ks_path}')
    if ret == 0:
        logger.info(f'Succeeded to create ks file: {ks_url}')
        return True
    raise FailException(f'Failed to create ks file: {ks_url}')


def base_packages_install(ssh, compose_id):
    """

    :param ssh:
    :param compose_id:
    :return:
    """
    ssh.runcmd('rm -f /var/lib/rpm/__db*;'
               'rm -rf /var/lib/yum/history/*.sqlite;'
               'rm -rf /var/cache/yum/; rpm --rebuilddb')
    if 'RHEL-7' in compose_id:
        cmd = ('yum clean all;'
               'yum install -y @core @x11 net-tools virt-who wget git nmap '
               'hostname subscription-manager pexpect expect libvirt-python')
    else:
        cmd = ('yum clean all;'
               'yum install -y @core @base-x net-tools virt-who '
               'wget git nmap expect hostname subscription-manager '
               'python3-pexpect python3-libvirt')
    ret, output = ssh.runcmd(cmd)
    if ret == 0:
        logger.info('Succeeded to install base required packages')
    raise FailException('Failed to install base required packages')


def grub_update(ssh, ks_url, vmlinuz_url, initrd_url, repo_url):
    """

    :param ssh:
    :param ks_url:
    :param vmlinuz_url:
    :param initrd_url:
    :param repo_url:
    :return:
    """
    base.url_validation(vmlinuz_url)
    base.url_validation(initrd_url)
    base.url_validation(repo_url)
    menu_title = 'rhel-reinstall'
    vmlinuz_name = 'vmlinuz-reinstall'
    initrd_name = 'initrd-reinstall.img'
    ssh.runcmd(f'rm -f /boot/{vmlinuz_name};'
               f'curl -L {vmlinuz_url} -o /boot/{vmlinuz_name};'
               f'sync')
    ssh.runcmd(f'rm -f /boot/{initrd_name};'
               f'curl -L {initrd_url} -o /boot/{initrd_name};'
               f'sync')
    repo = f'repo={repo_url}'
    rhel_ver = base.rhel_version(ssh)
    if rhel_ver == '6':
        cmd = (f'cat <<EOF > /boot/grub/grub.conf\n'
               f'default=0\n'
               f'timeout=5\n'
               f'splashimage=(hd0,0)/grub/splash.xpm.gz\n'
               f'hiddenmenu\n'
               f'title {menu_title}\n'
               f'root (hd0,0)\n'
               f'kernel /{vmlinuz_name} ksdevice=bootif ip=dhcp ks={ks_url} '
               f'{repo} quiet LANG=en_US.UTF-8 acpi=off\n'
               f'initrd /{initrd_name}\n'
               f'EOF')
        ssh.runcmd(cmd)
    else:
        cmd = ('cat <<EOF > /etc/grub.d/40_custom\n'
               '#!/bin/sh\n'
               'exec tail -n +3 \$0\n'
               "menuentry '%s' --class red --class gnu-linux --class gnu --class os {\n"
               'load_video\n'
               'set gfxpayload=keep\n'
               'insmod gzio\n'
               'insmod part_msdos\n'
               'insmod xfs\n'
               'set root="hd0,msdos1"\n'
               'linux16 /%s ksdevice=bootif ip=dhcp ks=%s %s quiet LANG=en_US.UTF-8 acpi=off\n'
               'initrd16 /%s\n'
               '}\n'
               'EOF'
               ) % (menu_title, vmlinuz_name, ks_url, repo, initrd_name)
        ssh.runcmd(cmd)
        ssh.runcmd('grub2-mkconfig -o /boot/grub2/grub.cfg')
        ssh.runcmd(f'grub2-set-default "{menu_title}"; grub2-editenv list')
    time.sleep(60)
    ssh.runcmd('sync;sync;sync;sync;reboot -f && exit')


def grub_arguments_parser():
    """
    Parse and convert the arguments from command line to parameters
    for function using, and generate help and usage messages for
    each arguments.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--rhel-compose',
        required=True,
        help='such as: RHEL-7.6-20181010.0, RHEL-8.0-20181005.1')
    parser.add_argument(
        '--host',
        default=config.local.server,
        required=False,
        help="The IP or Hostname where host's grub will be updated, "
             "default to the [local]:server in virtwho.ini")
    parser.add_argument(
        '--username',
        default=config.local.username,
        required=False,
        help="The ssh username of this host, "
             "default to the [local]:username in virtwho.ini")
    parser.add_argument(
        '--password',
        default=config.local.password,
        required=False,
        help="The ssh password of this host, "
             "default to the [local]:password in virtwho.ini")
    parser.add_argument(
        '--virtwho-resource',
        default=None,
        required=False,
        help='One of [compose, gating]')
    parser.add_argument(
        '--gating-msg',
        default=None,
        required=False,
        help='The message is required when --virt-resource=gating, '
             'which should be a json')
    return parser.parse_args()


if __name__ == "__main__":
    args = grub_arguments_parser()
    rhel_install_by_grub(args)
