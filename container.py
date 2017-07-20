import re
import ipaddress
import netaddr
from naming import Naming
import utility
import configuration
import socket
import asyncio
import asyncdocker
import docker
from models import Container, Port
from collections import namedtuple
from datetime import datetime
import iptc
from log import write

ContainerUpdate = namedtuple('ContainerUpdate', 'name ip port')


CTR_STATUS_STOPPED = 0
CTR_STATUS_STARTING = 1
CTR_STATUS_RUNNING = 2
CTR_STATUS_STOPPING = 3
CTR_STATUS_STOPPED = 4

BANNER = """   ____ __           __   _       __         __ 
  / __// /___ _ ___ / /_ (_)____ / /  ___ _ / /              
 / _/ / // _ `/(_-</ __// // __// /__/ _ `// _ \            
/___//_/ \_,_//___/\__//_/ \__//____/\_,_//_.__/ 
"""

CONTACT_INFO = """
Darren Southern 
@stillinsecure
https://github.com/stillinsecure/crouter
"""



class RunningContainer:

    def __init__(self, name):
        self.status = CTR_STATUS_STOPPED
        self.name = name
        self.last_seen = datetime.now()


class ContainerManager:

    EndPoint = namedtuple('EndPoint', 'port ip container_name')

    def __init__(self, config):

        self.client = asyncdocker.AsyncDocker()
        self.container_map_by_port = None
        self.container_map_by_ip = None
        self.containers = {}
        self.config = config

    def start(self):
        write(BANNER, 'green')
        write(CONTACT_INFO, 'yellow')

        self.create_containers()
        self.container_map_by_port, self.container_map_by_ip = self.build_container_map()

        for port in self.container_map_by_port:
            write('{} containers for port {}'.format(len(self.container_map_by_port[port]), port), 'red')
            for ip in self.container_map_by_port[port]:
                write('\t{}'.format(utility.IPAddress.int_to_str(ip)), 'green')

    async def monitor_idle_containers(self):
        while True:
            try:
                await asyncio.sleep(10)
                for key in list(self.containers.keys()):
                    container = self.containers[key]
                    if container.status is not CTR_STATUS_RUNNING:
                        continue
                    last_seen = (datetime.now() - container.last_seen).total_seconds()
                    if last_seen > 20:
                        container.status = CTR_STATUS_STOPPING
                        print('Stopping {}'.format(container.name))
                        await self.client.stop_container(container.name)
                        del self.containers[container.name]
            except:
                print('Error')

    def set_to_running(self, name):
        self.containers[name].status = CTR_STATUS_RUNNING

    async def start_if_not_running(self, ip, port):
        name = self.get_container_name(ip, port)
        if name not in self.containers:
            container = RunningContainer(name)
            # Need to set the status outside of the await call. Another task
            # may come in here during the await
            container.status = CTR_STATUS_STARTING
            self.containers[name] = container
            print('Starting container {} {}:{}'.format(name, ip, port))
            if await self.client.start_container(name):
                return name
            else:
                return None

        return name


    def update_container(self, container_name):
        if container_name in self.containers:
            self.containers[container_name].last_seen = datetime.now()

    def get_container_name(self, ip, port):
        port_map = self.container_map_by_port.get(port)
        if port_map is not None:
            name = port_map.get(ip)
            return name

    def get_container_name(self, ip):
        name = self.container_map_by_ip[ip]
        return name

    def __stop_all_containers(self):
        containers = Container.select()
        for container in containers:
            try:
                self.client.stop(container=container.name)
            except:
                pass

    def build_container_map(self):

        container_map_by_port = {}
        container_map_by_ip = {}

        end_points = Port.select(Port.value, Container.ip, Container.name)\
                         .join(Container)\
                         .order_by(Port.value)

        for end_point in end_points:
            port = end_point.value
            container = end_point.container
            if port not in container_map_by_port:
                container_map_by_port[port] = {}
            ip = utility.IPAddress.str_to_int(container.ip)
            container_map_by_port[port][ip] = container.name
            if ip not in container_map_by_ip:
                container_map_by_ip[ip] = container.name

        return container_map_by_port, container_map_by_ip

    def setup_images(self, images_cfg):
        write('Setting up images', 'white')

        client = docker.from_env()
        count = 0
        image_ports = {}
        unique_ports = []

        # Pull down images defined in the images if they are
        # not already present on the local system
        for image_cfg in images_cfg:
            try:
                image = client.images.get(image_cfg.name)
                count += image_cfg.count
                exposed_ports = list(image.attrs['ContainerConfig']['ExposedPorts'])
                for exposed_port in exposed_ports:
                    match  = re.search('^\d+(?=\/tcp$)', exposed_port)
                    if match is not None:
                        port = match.group(0)
                        if image_cfg.name not in image_ports:
                            image_ports[image_cfg.name] = []
                        image_ports[image_cfg.name].append(port)
                        if port not in unique_ports:
                            unique_ports.append(port)
                    else:
                        print(exposed_port)
            except docker.errors.NotFound:
                client.images.pull(image_cfg.name)

        return count, image_ports, unique_ports

    def generate_mac(self, ip):
        mac = '02:42'
        for octet in ip.split('.'):
            mac += ':{:02x}'.format(int(octet))
        return mac

    def setup_iptables(self, crouter_network, ports):
        write('Setting up iptables', 'white')

        # Flush existing MANGLE PREROUTING chain
        chain = iptc.Chain(iptc.Table(iptc.Table.MANGLE), 'PREROUTING')
        chain.flush()

        # Rule to send all tcp traffic for containers with matching ports to the NFQUEUE
        tcp_rule = iptc.Rule()
        tcp_rule.dst = crouter_network
        tcp_rule.protocol = 'tcp'
        tcp_match = tcp_rule.create_match('multiport')
        comma_ports = ','.join(list(ports))
        tcp_match.dports = comma_ports
        tcp_target = tcp_rule.create_target('NFQUEUE')
        tcp_target.set_parameter('queue-num', '0')
        chain.insert_rule(tcp_rule)

        # Rule to send all icmp traffic for containers to the NFQUEUE
        icmp_rule = iptc.Rule()
        icmp_rule.dst = crouter_network
        icmp_rule.protocol = 'icmp'
        icmp_target = icmp_rule.create_target('NFQUEUE')
        icmp_target.set_parameter('queue-num', '0')
        chain.insert_rule(icmp_rule)

        # Rule to send all output packets from the proxy back to the NFQUEUE
        proxy_rule = iptc.Rule()
        proxy_rule.src = '192.168.1.9'
        proxy_rule.protocol = 'tcp'
        proxy_match = proxy_rule.create_match('tcp')
        proxy_match.sport = '5996'
        proxy_target = proxy_rule.create_target('NFQUEUE')
        proxy_target.set_parameter('queue-num', '0')

        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), 'OUTPUT')
        chain.flush()
        chain.insert_rule(proxy_rule)

    def create_network(self, count):
        write('Creating network', 'white')

        network_cfg = self.config.network
        client = docker.from_env()

        try:
            network = client.networks.get(network_cfg.name)
            network.remove()
        except docker.errors.NotFound:
            pass

        # Add three to the number of containers to account for the gateway, network, broadcast address
        subnet = utility.IPAddress.generate_cidr(network_cfg.address, count+3)

        ip = netaddr.IPNetwork(subnet)

        # Calc the gateway as network address + 1
        gateway = utility.IPAddress.int_to_str(ip.first+1)

        # Broadcast is the last
        broadcast = utility.IPAddress.int_to_str(ip.last)

        addresses = [str(address) for address in list(netaddr.IPSet([subnet, ]))]

        if gateway in addresses:
            addresses.remove(gateway)
        if broadcast in addresses:
            addresses.remove(broadcast)
        if network_cfg.address in addresses:
            addresses.remove(network_cfg.address)\

        ipam_pool = docker.types.IPAMPool(subnet=subnet, gateway=gateway)
        ipam_config = docker.types.IPAMConfig(pool_configs=[ipam_pool])
        network = client.networks.create(name=network_cfg.name, ipam=ipam_config)

        return network, addresses, subnet

    def delete_containers(self):
        write('Deleting containers', 'white')
        client = docker.from_env()
        for container in client.containers.list(all=True):
            container.remove(v=True, force=True)
        Port.delete()
        Container.delete()

    def create_containers(self):
        client = docker.APIClient(base_url='unix://var/run/docker.sock')

        # Clean up all the containers
        self.delete_containers()

        # Make sure the defined images are available and config the ports
        count, image_ports, unique_ports = self.setup_images(self.config.images)

        # Create a network for the containers
        network, addresses, subnet = self.create_network(count)

        # Apply the iptable rules required for the configured images
        self.setup_iptables(subnet, unique_ports)

        write('Creating containers', 'white')

        # Create a unique list of host names
        naming = Naming()
        host_names = naming.generate_host_names(self.config.naming, count)

        for image in self.config.images:

            ports = image_ports[image.name]

            for count in range(image.count):
                host_name = host_names.pop()
                ip = addresses.pop()
                mac = self.generate_mac(ip)
                endpoint_config = client.create_endpoint_config(ipv4_address=ip)
                networking_config = client.create_networking_config({network.name : endpoint_config})
                container_id = client.create_container(image=image.name,
                                                       detach=True,
                                                       hostname=host_name,
                                                       name=host_name,
                                                       ports=ports,
                                                       networking_config=networking_config,
                                                       mac_address=mac)

                container = client.inspect_container(container_id)
                # Persist the container info to the db with the ports
                # Ports are used to determine what listeners to create
                new_container = Container.create(container_id=container["Id"],
                                                 name=host_name, ip=ip, mac=mac)
                for port in ports:
                    Port.create(container=new_container.id, value=port)




