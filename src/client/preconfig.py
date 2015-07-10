#!/usr/bin/env python

import argparse
import json
import logging
import paramiko
import os
import re
import sys

# Testbed Converter Version
__version__ = '1.0'

log = logging.getLogger('preconfig')
log.setLevel(logging.DEBUG)

class Utils(object):
    @staticmethod
    def initialize_logger(log_file='preconfig.log', log_level=40):
        log = logging.getLogger('preconfig')
        file_h = logging.FileHandler(log_file)
        file_h.setLevel(logging.DEBUG)
        stream_h = logging.StreamHandler(sys.stdout)
        stream_h.setLevel(log_level)
        long_format = '[%(asctime)-15s: %(filename)s:%(lineno)s:%(funcName)s: %(levelname)s] %(message)s'
        short_format = '[%(asctime)-15s: %(funcName)s] %(message)s'
        file_formatter = logging.Formatter(long_format)
        stream_formatter = logging.Formatter(short_format)
        file_h.setFormatter(file_formatter)
        stream_h.setFormatter(stream_formatter)
        log.addHandler(file_h)
        log.addHandler(stream_h)

    @staticmethod
    def is_file_exists(*filenames):
        for filename in filenames:
            filename = os.path.abspath(os.path.expanduser(filename))
            if not os.path.isfile(filename):
                raise RuntimeError('file (%s) does not exists' %filename)
        return filenames

    @staticmethod
    def parse_args(args):
        parser = argparse.ArgumentParser(description='Server Manager Lite Preconfig Utility',
                                         add_help=True)
        parser.add_argument('--version',
                            action='version',
                            version=__version__,
                            help='Print version and exit')
        parser.add_argument('-v', action='count', default=0,
                            help='Increase verbosity. -vvv prints more logs')
        parser.add_argument('--server-json',
                            required=True,
                            help='Absolute path to testbed file')
        parser.add_argument('--server-manager-ip',
                            required=True,
                            help='IP Address of Server Manager Node')
        parser.add_argument('--server-manager-port',
                            default=9003,
                            help='Port Number of Server Manager Node which hosts repos')        
        parser.add_argument('--log-file',
                            default='preconfig.log',
                            help='Absolute path of a file for logging')
        cliargs = parser.parse_args(args)
        if len(args) == 0:
            parser.print_help()
            sys.exit(2)
        Utils.is_file_exists(cliargs.server_json)

        # update log level and log file
        log_level = [logging.ERROR, logging.WARN, \
                     logging.INFO, logging.DEBUG]
        cliargs.v = cliargs.v if cliargs.v <= 3 else 3
        Utils.initialize_logger(log_file=cliargs.log_file,
                                log_level=log_level[cliargs.v])
        return cliargs

    @staticmethod
    def preconfig(cliargs):
        hosts = []
        with open(cliargs.server_json, 'r') as fid:
            contents = fid.read()
        server_json = json.loads(contents)
        for host_dict in server_json['server']:
            hostobj = Server(host_dict, args.server_manager_ip,
                             args.server_manager_port)
            hostobj.connect()
            hostobj.preconfig()
            hosts.append(hostobj)

class Server(object):
    def __init__(self, server_dict, server_manager_ip,
                 server_manager_port=9003):
        self.server_dict = server_dict
        self.server_manager_ip = server_manager_ip
        self.server_manager_port = server_manager_port
        self.connection = paramiko.SSHClient()
        self.connection_timeout = 5
        self.username = 'root'
        self.export_server_info()
        self.extra_packages = ['puppet', 'python-netaddr',
                               'ifenslave-2.6=1.1.0-19ubuntu5', 'sysstat',                             
                               'ethtool']

    def __del__(self):
        log.info('Disconnecting...')
        self.disconnect()

    def export_server_info(self):
        for key, value in self.server_dict.items():
            setattr(self, key, value)

    def set_mgmt_interface(self):
        self.mgmt_iface = self.network['management_interface']
    
    def set_mgmt_ip_address(self, ):
        self.set_mgmt_interface()
        for iface_dict in self.network['interfaces']:
            if iface_dict['name'] == self.mgmt_iface:
                self.ip, self.cidr = iface_dict['ip_address'].split('/')

    def connect(self):
        self.set_mgmt_ip_address()
        self.connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.connection.connect(self.ip, username=self.username, \
                                    password=self.password, \
                                    timeout=self.connection_timeout)
            log.info('Connected to Host (%s)' % self.ip)
        except Exception, err:
            log.error('ERROR: %s' % err)
            log.error('ERROR: Unable to connect Host (%s) with username(%s) ' \
                  'and password(%s)' % (self.ip, self.username, self.password))
            raise RuntimeError('Connection to (%s) Failed' % self.ip)
        
    def disconnect(self):
        self.connection.close()

    def exec_cmd(self, cmd, error_on_fail=False):
        exit_status = 1
        magic_pattern = r'001902803704605506407308209100'
        original_cmd = cmd
        cmd += ' && echo %s' % magic_pattern
        stdin, stdout, stderr = self.connection.exec_command(cmd)
        # check stderr is pending
        output = stdout.read()
        if output.count(magic_pattern) > 0:
            exit_status = 0
            output = re.sub(r'%s\n$' % magic_pattern, '', output, 1)

        if exit_status:
            log.error('Cmd (%s) Failed' % cmd)
            log.error('%s' % stderr.read())

        if error_on_fail and exit_status:
            log.error('[error_on_fail]: Cmd (%s) Failed' % original_cmd)
            raise RuntimeError('[error_on_fail]: Cmd (%s) Failed' % original_cmd)
        return exit_status, output
    
    def preconfig(self):
        self.preconfig_hosts_file()
        self.preconfig_unauthenticated_packages()
        self.preconfig_repos()
        self.install_packages()
        #self.setup_interface()
        self.preconfig_ntp_config()
        self.preconfig_puppet_config()

    def verify_puppet_host(self):
        ping_cmd = r'ping -q -c 1 puppet > /dev/null 2>@1'
        status, output = self.exec_cmd(ping_cmd)
        if status:
            log.info('Seems puppet host is not configured')
            log.info('Adding puppet alias to /etc/hosts file')
            puppet_cmd = 'echo %s puppet >> /etc/hosts' % self.server_manager_ip
            self.exec_cmd(puppet_cmd, error_on_fail=True)
            log.debug('Verify puppet host after configuration')
            self.exec_cmd(ping_cmd, error_on_fail=True)       
    
    def verify_setup_hostname(self):
        if not self.id:
            log.error('Hostname is not configured')
            raise RuntimeError('Hostname is not configured for (%s)' % self.ip)

    def preconfig_hosts_file(self):
        self.verify_puppet_host()
        self.verify_setup_hostname()

    def preconfig_unauthenticated_packages(self):
        apt_auth = r'APT::Get::AllowUnauthenticated \"true\"\;'
        status, output = self.exec_cmd('grep --quiet \"^%s\" /etc/apt/apt.conf' % apt_auth)
        if status:
            log.info('Configure Allow Unauthenticated true')
            self.exec_cmd('echo %s >> /etc/apt/apt.conf' % apt_auth, error_on_fail=True)
    
    def preconfig_repos(self):
        repo_entry = r'deb http://%s:%s/thirdparty_packages/ ./' % (self.server_manager_ip, self.server_manager_port)
        repo_entry_verify = r'%s:%s\/thirdparty_packages' % (self.server_manager_ip, self.server_manager_port)
        status, output = self.exec_cmd('apt-cache policy | grep %s' % repo_entry_verify)
        if status:
            log.info('/etc/apt/sources.list has no thirdparty_packages '
                     'repo entry')
            log.debug('Backup existing sources.list')
            self.exec_cmd(r'cp /etc/apt/sources.list '\
                          '/etc/apt/sources.list_$(date +%Y_%m_%d__%H_%M_%S).contrailbackup')
            log.debug('Adding Repo Entry (%s) to /etc/apt/sources.list' % repo_entry)
            self.exec_cmd('echo >> /etc/apt/sources.list', error_on_fail=True)
            self.exec_cmd(r"sed -i '1 i\%s' /etc/apt/sources.list" % repo_entry)
            self.exec_cmd('apt-get update')
            self.exec_cmd('apt-cache policy | grep %s' % repo_entry_verify,
                          error_on_fail=True)
    
    def install_packages(self):
        for package in self.extra_packages:
            self.exec_cmd('apt-get -y install %s' % package,
                          error_on_fail=True)

    def verify_interface_ip(self, interface, ip):
        return self.exec_cmd('ip addr show %s | grep %s' % (interface, ip))

    def exec_setup_interface(self, iface_info, error_on_fail=True):
        cmd = '/opt/contrail/bin/interface_setup.py '
        cmd += '--device %s --ip %s ' % (iface_info['name'],
                                         iface_info['ip_address'])
        if 'member_interfaces' in iface_info.keys():
            cmd += '--members %s ' % " ".join(iface_info['member_interfaces'])
        if 'gateway' in iface_info.keys():
            cmd += '--gw %s ' % iface_info['gateway']
        if 'vlan' in iface_info.keys():
            cmd += '--vlan %s ' % iface_info['vlan']
        if 'bond_options' in iface_info.keys():
            cmd += '--bond-opts %s' % json.dumps(iface_info['bond_options'])
        status, output = self.exec_cmd(cmd)
        if error_on_fail and status:
            raise RuntimeError('Setup Interface failed for ' \
                               'Iface Info (%s)' % iface_info)
        return status, output

    def setup_interface(self):
        sftp_connection = self.connection.open_sftp()
        self.exec_cmd('mkdir -p /opt/contrail/bin/')
        sftp_connection.put('/var/www/html/kickstarts/interface_setup.py',
                            '/opt/contrail/bin/interface_setup.py')
        self.exec_cmd('chmod 755 /opt/contrail/bin/interface_setup.py')
        for iface_info in self.network['interfaces']:
            status, output = self.verify_interface_ip(iface_info['name'],
                                                      iface_info['ip_address'])
            if not status:
                log.warn('Interface (%s) already configured with ' \
                         'IP Address (%s)' % (iface_info['name'],
                                              iface_info['ip_address']))
            else:
                self.exec_setup_interface(iface_info)
    
    def check_ntp_status(self):
        status, output = self.exec_cmd(r'ntpdc -nc sysinfo | grep "system peer.*0.0.0.0"')
        if not status:
            self.setup_ntp()
        status, output = self.exec_cmd(r'ntpdc -nc sysinfo | grep "system peer.*%s$"' % self.server_manager_ip)
        if status:
            self.exec_cmd(r'echo "server %s\n" >> /etc/ntp.conf' % self.server_manager_ip)
    
    def setup_ntp(self, ):
        log.debug('Install ntp package')
        self.exec_cmd('apt-get -y install ntp', error_on_fail=True)
        log.debug('Setup NTP configuration')
        self.exec_cmd('ntpdate %s' % self.server_manager_ip)
        log.debug('Backup existing ntp.conf')
        self.exec_cmd(r'mv /etc/ntp.conf /etc/ntp.conf.$(date +%Y_%m_%d__%H_%M_%S)',
                      error_on_fail=True)
        self.exec_cmd('touch /var/lib/ntp/drift', error_on_fail=True)
        ntp_config = 'driftfile /var/lib/ntp/drift\n' \
                     'server %s\n' \
                     'restrict 127.0.0.1\n' \
                     'restrict -6 ::1\n' \
                     'includefile /etc/ntp/crypto/pw\n' \
                     'keys /etc/ntp/keys' % self.server_manager_ip
        self.exec_cmd(r'echo "%s" >> /etc/ntp.conf' % ntp_config,
                      error_on_fail=True)
        self.exec_cmd('service ntp restart', error_on_fail=True)
    
    def preconfig_ntp_config(self):
        self.check_ntp_status()

    def setup_puppet_configs(self, ):
        log.info('Setup puppet Configs')
        puppet_config = '[agent]\n' \
                        'pluginsync = true\n' \
                        'ignorecache = true\n' \
                        'usecacheonfailure = false\n' \
                        'listen = true\n' \
                        'ordering = manifest\n' \
                        '[main]\n' \
                        'runinterval = 10\n' \
                        'configtimeout = 500'
        self.exec_cmd(r'echo "%s" >> /etc/puppet/puppet.conf' % puppet_config,
                      error_on_fail=True)
        
    def preconfig_puppet_config(self):
        self.setup_puppet_configs()
    
if __name__ == '__main__':
    args = Utils.parse_args(sys.argv[1:])
    log.info('Executing: %s' % " ".join(sys.argv))
    Utils.preconfig(args)