#!/usr/bin/env python

import ast
import argparse
from collections import defaultdict
from functools import wraps
import json
import paramiko
import os
import re
import sys

# Testbed Converted Version
__version__ = '1.0'

class Utils(object):
    @staticmethod
    def is_file_exists(*filenames):
        for filename in filenames:
            filename = os.path.abspath(os.path.expanduser(filename))
            if not os.path.isfile(filename):
                raise RuntimeError('file (%s) does not exists' %filename)
        return filenames

    @staticmethod
    def parse_args(args):
        parser = argparse.ArgumentParser(description='TestBed Conversion Utility',
                                         add_help=True)
        parser.add_argument('--version', '-v',
                            action='version',
                            version=__version__,
                            help='Print version and exit')
        parser.add_argument('--testbed',
                            help='Absolute path to testbed file')
        parser.add_argument('--contrail-packages',
                            nargs='+',
                            required=True,
                            help='Absolute path to Contrail Package file, '\
                                 'Multiple files can be separated with space')
        parser.add_argument('--contrail-storage-packages',
                            nargs='+',
                            default=[],
                            help='Absolute path to Contrail Storage Package file, '\
                                 'Multiple files can be separated with space')
        cliargs = parser.parse_args(args)
        if len(args) == 0:
            parser.print_help()
            sys.exit(2)
        if cliargs.contrail_packages:
            cliargs.contrail_packages = [('contrail_packages', pkg_file) \
                for pkg_file in Utils.is_file_exists(*cliargs.contrail_packages)]

        if cliargs.contrail_storage_packages:
            cliargs.contrail_storage_packages = [('contrail_storage_packages', pkg_file) \
                for pkg_file in Utils.is_file_exists(*cliargs.contrail_storage_packages)]
        return cliargs

    @staticmethod
    def converter(args):
        testsetup = TestSetup(testbed=args.testbed)
        testsetup.connect()
        testsetup.update()
        server_json = ServerJsonGenerator(testsetup=testsetup)
        server_json.generate_json_file()
        cluster_json = ClusterJsonGenerator(testsetup=testsetup)
        cluster_json.generate_json_file()
        package_files = args.contrail_packages + args.contrail_storage_packages
        image_json = ImageJsonGenerator(testsetup=testsetup,
                                        package_files=package_files)
        image_json.generate_json_file()

class Host(object):
    def __init__(self, ip, username, password, **kwargs):
        self.connection = paramiko.SSHClient()
        self.iface_data_raw = ''
        self.iface_data_all = ''
        self.route_data_raw = ''
        self.ip = ip
        self.username = username
        self.password = password
        self.host_id = '%s@%s' % (username, ip)
        self.timeout = kwargs.get('timeout', 5)

    def __del__(self):
        print 'Disconnecting...'
        self.disconnect()

    def connect(self):
        self.connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.connection.connect(self.ip, username=self.username, \
                                    password=self.password, \
                                    timeout=self.timeout)
            print 'Connected to Host (%s)' % self.ip
        except Exception, err:
            print 'ERROR: ', err
            print 'ERROR: Unable to connect Host (%s) with username(%s) ' \
                  'and password(%s)' % (self.ip, self.username, self.password)
            raise RuntimeError('Connection to (%s) Failed' % self.ip)


    def disconnect(self):
        self.connection.close()

    def exec_cmd(self, cmd):
        stdin, stdout, stderr = self.connection.exec_command(cmd)
        # check stderr is pending
        return stdout.read()

    def retrieve_iface_info(self):
        output = self.exec_cmd('ip address list')
        return output.strip()

    def retrieve_route_info(self):
        output = self.exec_cmd('ip route list')
        return output.strip()

    def retrieve_hostname(self):
        output = self.exec_cmd('hostname -s')
        return output.strip()

    def retrieve_domain_name(self):
        output = self.exec_cmd('hostname -d')
        return output.strip()

    def retrieve_ostype(self):
        output = self.exec_cmd("python -c 'from platform import linux_distribution; \
                               print linux_distribution()'")
        return output.strip()

    def parse_iface_info(self, iface_data=None):
        parsed_data = {}
        pattern = r'^\d+\:\s+\w+\:\s+'
        iface_pattern = r'^\d+\:\s+(\w+)\:\s+(.*)'
        iface_data = iface_data or self.retrieve_iface_info()

        iters = re.finditer(pattern, iface_data, re.M|re.DOTALL)
        indices = [match.start() for match in iters]
        matched = map(iface_data.__getslice__, indices, indices[1:] + [len(iface_data)])
        for match in matched:
            if_match = re.search(iface_pattern, match, re.M|re.DOTALL)
            if if_match:
                parsed_data[if_match.groups()[0]] = if_match.groups()[1]
        return parsed_data

    def parse_route_info(self, route_data=None):
        route_data = route_data or self.retrieve_route_info()
        return route_data.split('\r\n')

    def get_actual_ostype(self):
        version_raw = self.retrieve_ostype()
        dist, version, extra = ast.literal_eval(version_raw)
        return dist, version, extra

    def set_actual_ostype(self):
        dist, version, extra = self.get_actual_ostype()
        if 'red hat' in dist.lower():
            dist = 'redhat'
        elif 'centos linux' in dist.lower():
            dist = 'centoslinux'
        self.actual_ostype = (dist.lower(), version, extra)

    def get_mac_from_ifconfig(self, iface_data=None):
        mac = ''
        if iface_data is None:
            iface_data = self.iface_data_raw
        ether_pattern = re.compile(r'\bether\s([^\s]+)\b')
        ether_match = ether_pattern.search(iface_data)
        if ether_match:
            mac = ether_match.groups()[0]
        return mac

    def get_ip_from_ifconfig(self, iface_data=None):
        ip_net = []
        if iface_data is None:
            iface_data = self.iface_data_raw
        inet_pattern = re.compile(r'\binet\s([^\s]+)\b')
        inet_match = inet_pattern.search(iface_data)
        if inet_match:
            ip_net = inet_match.groups()[0].split('/')
        return ip_net

    def get_interface_details_from_ip(self, ip=None):
        interface = matched_data = ''
        if ip is None:
            ip = self.ip
        iface_info = self.parse_iface_info()
        for iface, iface_data in iface_info.items():
            if re.search(r'\binet\s+%s' % ip, iface_data):
                matched_data = iface_data
                interface = iface
        return interface, matched_data

    def set_route_data(self):
        self.route_data_raw = self.parse_route_info()

    def get_default_gateway(self, route_data=None):
        if route_data is None:
            route_data = self.parse_route_info()
        pattern = re.compile(r'\bdefault\s+via\s+([^\s]+)\b')
        for route_info in route_data:
            match = pattern.search(route_info)
            if match:
                gw = match.groups()[0]
        return gw

    def get_if_dhcp_enabled(self):
        pass

    def get_hostname(self):
        return self.retrieve_hostname()

    def get_domain_name(self):
        return self.retrieve_domain_name()

    def set_interface_details_from_ip(self, ip=None):
        if ip is None:
            ip = self.ip
        self.interface, self.iface_data_raw = self.get_interface_details_from_ip(ip)

    def set_route_data(self):
        self.route_data_raw = self.get_route_data()

    def set_ip_from_ifconfig(self, iface_data=None):
        self.ip_net = self.get_ip_from_ifconfig(iface_data)

    def set_mac_from_ifconfig(self, iface_data=None):
        self.mac = self.get_mac_from_ifconfig(iface_data)

    def set_default_gateway(self):
        self.default_gateway = self.get_default_gateway()

    def set_domain_name(self):
        self.domain_name = self.get_domain_name()

    def set_if_dhcp_enabled(self):
        pass

    def set_ostype(self, ostypes):
        self.ostypes = ostypes

    def set_roles(self, roles):
        self.roles = roles

    def set_hypervisor(self, hypervisor):
        self.hypervisor = hypervisor

    def set_storage_node_configs(self, configs):
        self.storage_node_configs = configs

    def set_dpdk_configs(self, configs):
        self.dpdk_config = configs

    def set_vrouter_module_params(self, params):
        self.vrouter_module_params = params

    def set_virtual_gateway(self, configs):
        self.vgw = configs

    def set_bond_info(self, bond_info):
        self.bond = bond_info

    def set_control_data(self, control_data):
        self.control_data = control_data

    def set_static_route(self, static_route):
        self.static_route = static_route

    def set_tor_agent(self, configs):
        self.tor_agent = configs

    def set_hostname(self):
        self.hostname = self.get_hostname()

    def update(self):
        self.set_actual_ostype()
        self.set_interface_details_from_ip()
        self.set_ip_from_ifconfig()
        self.set_mac_from_ifconfig()
        self.set_hostname()
        self.set_if_dhcp_enabled()
        self.set_domain_name()
        self.set_default_gateway()

class Testbed(object):
    def __init__(self, testbed):
        self.testbed_file = testbed
        self.testbed = None
        self.import_testbed()
        self.exclude_roles = ['all', 'build']

    def import_testbed(self):
        testbed_file = os.path.split(self.testbed_file)
        sys.path.append(testbed_file[0])
        testbed_name = testbed_file[1].strip('.py')
        try:
            self.testbed = __import__(testbed_name)
        except Exception, err:
            print "ERROR: %s" % err
            raise RuntimeError('Error while importing testbed file (%s)' % self.testbed_file)


class TestSetup(Testbed):
    def __init__(self, testbed):
        super(TestSetup, self).__init__(testbed=testbed)
        self.host_ids = []
        self.hosts = defaultdict(dict)
        self.import_testbed_variables()
        self.import_testbed_env_variables()
        self.set_host_ids()
        self.set_hosts()

    def set_hosts(self):
        for host_id in self.host_ids:
            username, host_ip = host_id.split('@')
            password = self.passwords.get(host_id, None)
            if password is None:
                raise RuntimeError('No Password defined for Host ID (%s)' % host_id)
            self.hosts[host_id] = Host(host_ip, username=username, password=password)

    def get_host_ids(self):
        return self.testbed.env.roledefs['all']

    def set_host_ids(self):
        self.host_ids = self.get_host_ids()

    def connect(self):
        for host_obj in self.hosts.values():
            host_obj.connect()

    def update(self):
        self.update_hosts()
        self.update_testbed()

    def update_hosts(self):
        for host_obj in self.hosts.values():
            host_obj.update()

    def update_testbed(self):
        self.set_testbed_ostype()
        self.update_host_roles()
        self.update_host_ostypes()
        self.update_host_hypervisor()
        self.update_host_bond_info()
        self.update_host_control_data()
        self.update_host_static_route()
        self.update_host_vrouter_params()

    def import_testbed_variables(self):
        for key, value in self.testbed.__dict__.items():
            if key.startswith('__') and key.endswith('__'):
                continue
            setattr(self, key, value)

    def import_testbed_env_variables(self):
        for key, value in self.testbed.env.items():
            setattr(self, key, value)

    def is_defined(variable):
        def _is_defined(function):
            @wraps(function)
            def wrapped(self, *args, **kwargs):
                try:
                    getattr(self, variable)
                    return function(self, *args, **kwargs)
                except:
                    return
            return wrapped
        return _is_defined

    def get_roles(self):
        host_dict = defaultdict(list)
        for role, hosts in self.roledefs.items():
            for host in hosts:
                host_dict[host].append(role)
        return host_dict

    def update_host_roles(self):
        host_dict = self.get_roles()
        for host_id, roles in host_dict.items():
            # Not required in SM environment
            if roles.count('all') > 0:
                roles.remove('all')
            if roles.count('build') > 0:
                roles.remove('build')
            if roles.count('cfgm') > 0:
                roles.remove('cfgm')
                roles.append('config')
            self.hosts[host_id].set_roles(roles)

    def get_testbed_ostype(self):
        hostobj = self.hosts.values()[0]
        return hostobj.actual_ostype

    def set_testbed_ostype(self):
        self.os_type = self.get_testbed_ostype()

    @is_defined('ostypes')
    def update_host_ostypes(self):
        for host_id, os_type in self.ostypes.items():
            self.hosts[host_id].set_ostype(os_type)

    @is_defined('hypervisor')
    def update_host_hypervisor(self):
        for host_id, hypervisor in self.hypervisor.items():
            self.hosts[host_id].set_hypervisor(hypervisor)

    @is_defined('bond')
    def update_host_bond_info(self):
        for host_id, bond_info in self.bond.items():
            self.hosts[host_id].set_bond_info(bond_info)

    @is_defined('control_data')
    def update_host_control_data(self):
        for host_id, control_data in self.control_data.items():
            self.hosts[host_id].set_control_data(control_data)

    @is_defined('static_route')
    def update_host_static_route(self):
        for host_id, static_route in self.static_route.items():
            self.hosts[host_id].set_static_route(static_route)

    @is_defined('storage_node_config')
    def update_storage_node_configs(self):
        for host_id, config in self.storage_node_config.items():
            self.hosts[host_id].set_storage_node_configs(config)

    @is_defined('vgw')
    def update_virtual_gateway(self):
        for host_id, config in self.vgw.items():
            self.hosts[host_id].set_virtual_gateway(config)

    @is_defined('tor_agent')
    def update_tor_agent_info(self):
        for host_id, config in self.tor_agent.items():
            self.hosts[host_id].set_tor_agent(config)

    @is_defined('dpdk')
    def update_hosts_dpdk_info(self):
        for host_id, dpdk_info in self.dpdk.items():
            self.hosts[host_id].set_dpdk_configs(dpdk_info)

    @is_defined('vrouter_module_params')
    def update_host_vrouter_params(self):
        for host_id, vrouter_params in self.vrouter_module_params.items():
            self.hosts[host_id].set_vrouter_module_params(vrouter_params)


class BaseJsonGenerator(object):
    def __init__(self, **kwargs):
        self.testsetup = kwargs.get('testsetup', None)
        name = kwargs.get('name', 'contrail')
        abspath = kwargs.get('abspath', None)
        self.package_files = kwargs.get('package_files', None)
        self.jsonfile = abspath or '%s.json' % name
        self.cluster_id = "cluster"
        self.dict_data = {}

    def set_if_defined(self, source_variable_name,
                       destination_variable, **kwargs):
        destination_variable_name = kwargs.get('destination_variable_name',
                                               source_variable_name)
        source_variable = kwargs.get('source_variable', self.testsetup)
        function = kwargs.get('function', getattr)
        value = function(source_variable, source_variable_name, None)
        if value is not None:
            destination_variable[destination_variable_name] = value

    def generate(self):
        with open(self.jsonfile, 'w') as fid:
            fid.write('%s\n' % json.dumps(self.dict_data, sort_keys=True,
                                          indent=4, separators=(',', ': ')))

class ServerJsonGenerator(BaseJsonGenerator):
    def __init__(self, testsetup, **kwargs):
        kwargs.update([('name', 'server')])
        super(ServerJsonGenerator, self).__init__(testsetup=testsetup, **kwargs)
        self.dict_data = {"server": []}

    def _initialize(self, hostobj):
        server_dict = {"id": hostobj.hostname,
                       "roles": hostobj.roles,
                       "cluster_id": self.cluster_id,
                       "password": hostobj.password,
                       "domain": hostobj.domain_name,
                       "network": {
                           "management_interface": hostobj.interface,
                           "provisioning": "kickstart",
                           "interfaces": [
                                {
                                "default_gateway": hostobj.default_gateway,
                                "ip_address": hostobj.ip,
                                "mac_address": hostobj.mac,
                                "name": hostobj.interface,
                                }  ]
                            }
                        }
        return server_dict

    def update_bond_details(self, server_dict, hostobj):
        bond_dict = {"name": hostobj.bond['name'],
                     "type": 'bond',
                     "bond_options": {},
                     }
        if 'member' in hostobj.bond.keys():
            bond_dict['member_interfaces'] = hostobj.bond['member']
        if 'mode' in hostobj.bond.keys():
            bond_dict['bond_options']['mode'] = hostobj.bond['mode']
        if 'xmit_hash_policy' in hostobj.bond.keys():
            bond_dict['bond_options']['xmit_hash_policy'] = hostobj.bond['xmit_hash_policy']
        return bond_dict

    def update_static_route_info(self, server_dict, hostobj):
        if getattr(hostobj, 'static_route', None) is None:
            return server_dict
        # TBD
        return server_dict

    def update_control_data_info(self, server_dict, hostobj):
        if getattr(hostobj, 'control_data', None) is None:
            return server_dict
        server_dict['contrail'] = {"control_data_interface": hostobj.control_data['device']}
        if hostobj.control_data['device'].startswith('bond'):
            control_data_dict = self.update_bond_details(server_dict, hostobj)
        else:
            control_data_dict = {"name": hostobj.control_data['name']}
        control_data_dict["ip_address"] = hostobj.control_data['ip']
        self.set_if_defined('gw', control_data_dict,
                            source_variable=hostobj.control_data,
                            function=dict.get,
                            destination_variable_name='gateway')
        self.set_if_defined('vlan', control_data_dict,
                            source_variable=hostobj.control_data,
                            function=dict.get)

        server_dict['network']['interfaces'].append(control_data_dict)
        return server_dict

    def update_network_details(self, server_dict, hostobj):
        server_dict = self.update_control_data_info(server_dict, hostobj)
        server_dict = self.update_static_route_info(server_dict, hostobj)
        return server_dict

    def update(self):
        for host_id in self.testsetup.hosts:
            hostobj = self.testsetup.hosts[host_id]
            server_dict = self._initialize(hostobj)
            server_dict = self.update_network_details(server_dict, hostobj)
            self.dict_data['server'].append(server_dict)

    def generate_json_file(self):
        self.update()
        self.generate()

class ClusterJsonGenerator(BaseJsonGenerator):
    def __init__(self, testsetup, **kwargs):
        kwargs.update([('name', 'cluster')])
        super(ClusterJsonGenerator, self).__init__(testsetup=testsetup, **kwargs)
        self.dict_data = {"cluster": []}

    def _initialize(self):
        cluster_dict = {"id": self.cluster_id}
        cluster_dict['parameters'] = {}
        self.set_if_defined('router_asn', cluster_dict['parameters'])
        self.set_if_defined('database_dir', cluster_dict['parameters'])
        self.set_if_defined('multi_tenancy', cluster_dict['parameters'])
        self.set_if_defined('encap_priority', cluster_dict['parameters'],
                            destination_variable_name='encapsulation_priority')
        self.set_if_defined('database_ttl', cluster_dict['parameters'],
                            destination_variable_name='analytics_data_ttl')
        self.set_if_defined('haproxy', cluster_dict['parameters'])
        self.set_if_defined('minimum_diskGB', cluster_dict['parameters'],
                            destination_variable_name='database_minimum_diskGB')
        self.set_if_defined('ext_routers', cluster_dict['parameters'])
        return cluster_dict

    def generate_json_file(self):
        cluster_dict = self._initialize()
        self.dict_data['cluster'].append(cluster_dict)
        self.generate()

class ImageJsonGenerator(BaseJsonGenerator):
    def __init__(self, testsetup, package_files, **kwargs):
        kwargs.update([('name', 'image')])
        super(ImageJsonGenerator, self).__init__(testsetup=testsetup,
                                                 package_files=package_files,
                                                 **kwargs)
        self.dict_data = {"image": []}
        self.package_types = {'deb': 'package', 'rpm': 'package',
                             'iso': 'image', 'tgz': 'tgz',
                             'tar.gz': 'tgz'}

    def get_version(self, package_file):
        version = ''
        # only rpm or deb version can be retrieved
        if not (package_file.endswith('.rpm') or package_file.endswith('.deb')):
            return ""
        if self.testsetup.os_type[0] in ['centos', 'fedora', 'redhat', 'centoslinux']:
            cmd = "rpm -qp --queryformat '%%{VERSION}-%%{RELEASE}\\n' %s" % package_file
        elif self.testsetup.os_type[0] in ['ubuntu']:
            cmd = "dpkg-deb -f %s Version" % package_file
        else:
            raise Exception("ERROR: UnSupported OS Type (%s)" % self.testsetup.os_type)
        pid = os.popen(cmd)
        version = pid.read().strip()
        pid.flush()
        return version

    def get_category(self, package_file):
        category = 'package'
        ext = filter(package_file.endswith, self.package_types.keys())
        if ext:
            category = self.package_types.get(ext[0], category)
        return category

    def get_package_type(self, package_type):
        dist = self.testsetup.os_type[0]
        package_type = package_type.split('_')
        package_type.insert(1, dist)
        return "_".join(package_type)

    def _initialize(self, package_file, package_type):
        image_dict = {
            "id": "image-1",
            "category": self.get_category(package_file),
            "version": self.get_version(package_file),
            "type": self.get_package_type(package_type),
            "path": package_file,
        }
        return image_dict

    def generate_json_file(self):
        for package_type, package_file in self.package_files:
            image_dict = self._initialize(package_file, package_type)
            self.dict_data['image'].append(image_dict)
            self.generate()

if __name__ == '__main__':
    args = Utils.parse_args(sys.argv[1:])
    Utils.converter(args)