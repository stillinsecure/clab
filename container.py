import re
import netaddr
from utility import Dictionary
import utility
import asyncio
import asyncdocker
import docker
import iptc
import logging
from naming import Naming
from models import Container, Port
from collections import namedtuple
from datetime import datetime

TCP_PROTOCOL_TXT = 'tcp'
UDP_PROTOCOL_TXT = 'udp'
TCP_PROTOCOL = 6
UDP_PROTOCOL = 17

ContainerUpdate = namedtuple('ContainerUpdate', 'name ip port')
ExposedPort = namedtuple('ExposedPort', 'num text protocol')

CTR_STATUS_STOPPED = 0
CTR_STATUS_STARTING = 1
CTR_STATUS_RUNNING = 2
CTR_STATUS_STOPPING = 3
CTR_STATUS_STOPPED = 4


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
        self.task = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def view(self, container_map_by_port=None, container_map_by_ip=None):
        if container_map_by_port is None or container_map_by_ip is None:
            container_map_by_port, container_map_by_ip = self.build_container_map()

        for port in container_map_by_port:
            print('{} container(s) for port {}'.format(len(container_map_by_port[port]), port), 'red')
            for ip in container_map_by_port[port]:
                print('\t{}'.format(utility.Net.ipint_to_str(ip)), 'green')

    def start(self):
        logging.info('Starting container manager')
        self.container_map_by_port, self.container_map_by_ip = self.build_container_map()
        self.view(self.container_map_by_port, self.container_map_by_ip)
        self.task = asyncio.ensure_future(self.monitor_idle_containers())

    def stop(self):
        logging.info('Stopping container manager')
        self.client.close()

    async def monitor_idle_containers(self):
        logging.info('Monitoring idle containers')

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
                        logging.info('Stopping the container %s', container.name)
                        await self.client.stop_container(container.name)
                        del self.containers[container.name]
            except:
                print('Error')

    def set_to_running(self, name):
        self.containers[name].status = CTR_STATUS_RUNNING

    async def start_if_not_running(self, ip, port, protocol):
        container = self.get_container_by_endpoint(ip, port, protocol)
        if container not in self.containers:
            running_container = RunningContainer(container.name)
            # Need to set the status outside of the await call. Another task
            # may come in here during the await
            running_container.status = CTR_STATUS_STARTING
            self.containers[container.name] = running_container
            logging.info('Starting container {} {}:{}'.format(container.name, ip, port))
            if await self.client.start_container(container.name):
                return container.name
            else:
                return None

        return container.name

    def update_container(self, container_name):
        if container_name in self.containers:
            self.containers[container_name].last_seen = datetime.now()

    def get_port_map_key(self, port, protocol):
        return int(''.join([str(protocol), str(port)]))

    def get_container_by_endpoint(self, ip, port, protocol):
        port_map_key = self.get_port_map_key(port, protocol)
        port_map = self.container_map_by_port.get(port_map_key)
        if port_map is not None:
            container = port_map.get(ip)
            return container

    def get_container_by_ip(self, ip):
        if ip in self.container_map_by_ip:
            return self.container_map_by_ip[ip]
        return None

    def stop_all_containers(self):
        containers = Container.select()
        for container in containers:
            try:
                self.client.stop(container=container.name)
            except:
                pass

    def build_container_map(self):
        container_map_by_port = {}
        container_map_by_ip = {}

        end_points = Port.select(Port.number, Port.protocol, Container.ip, Container.name)\
                         .join(Container)\
                         .order_by(Port.number)

        for end_point in end_points:
            port_key = self.get_port_map_key(end_point.number, end_point.protocol)
            container = end_point.container

            if port_key not in container_map_by_port:
                container_map_by_port[port_key] = {}

            ip = utility.Net.ipstr_to_int(container.ip)
            container_map_by_port[port_key][ip] = container

            if ip not in container_map_by_ip:
                container_map_by_ip[ip] = container

        return container_map_by_port, container_map_by_ip

    def setup_images(self, images_cfg):
        print('Setting up images', 'white')

        client = docker.from_env()
        count = 0
        image_ports = {}
        unique_ports = []

        # Pull down images defined in the images if they are
        # not already present on the local system
        for image_cfg in images_cfg:
            try:
                image = client.images.get(image_cfg.name)

                if Dictionary.has_attr(image.attrs, 'ContainerConfig', 'ExposedPorts'):
                    count += image_cfg.count
                    attr = Dictionary.get_attr(image.attrs, 'ContainerConfig', 'ExposedPorts')
                    exposed_ports = list(attr)

                    for exposed_port in exposed_ports:
                        match = re.search('(\d+)\/(tcp|udp)', exposed_port)

                        if match is not None:
                            port_num = match.group(1)
                            protocol = match.group(2)

                            if protocol == TCP_PROTOCOL_TXT:
                                protocol = TCP_PROTOCOL
                            elif protocol == UDP_PROTOCOL_TXT:
                                protocol = UDP_PROTOCOL

                            port = ExposedPort(port_num, exposed_port, protocol)

                            if image_cfg.name not in image_ports:
                                image_ports[image_cfg.name] = []
                            image_ports[image_cfg.name].append(port)

                            if port_num not in unique_ports:
                                unique_ports.append(port)

            except docker.errors.NotFound:
                client.images.pull(image_cfg.name)

        assert count > 0, 'No images have been defined'
        return count, image_ports, unique_ports

    def create_dnsmasq_conf(self):
        conf_file = '/etc/dnsmasq.d/{}.conf'.format(self.config.network.domain)
        with open(conf_file, 'w') as f:
            containers = Container.select()
            for container in containers:
                entry = 'address=/{}.{}/{}\r\n'.format(container.name, self.config.network.domain, container.ip)
                f.write(entry)

    def setup_iptables(self, crouter_network, ports):
        print('Setting up iptables', 'white')

        assert crouter_network is not None and len(crouter_network) > 1, 'A network address is required'
        assert ports is not None and len(ports) >= 1, 'Images need to be configured with TCP ports'

        # Flush existing MANGLE PREROUTING chain
        prerouting_chain = iptc.Chain(iptc.Table(iptc.Table.MANGLE), 'PREROUTING')

        dst = utility.Net.cidr_to_iptables_dst(crouter_network)
        src = '{}/255.255.255.255'.format(self.config.router.get_interface_ip())

        for rule in prerouting_chain.rules:
            if rule.dst == dst:
                prerouting_chain.delete_rule(rule)

        tcp_ports = [str(port.num) for port in ports if port.protocol == TCP_PROTOCOL]
        udp_ports = [str(port.num) for port in ports if port.protocol == UDP_PROTOCOL]

        # Rule to send all tcp traffic for containers with matching ports to the NFQUEUE
        if tcp_ports is not None:
            tcp_rule = iptc.Rule()
            tcp_rule.dst = crouter_network
            tcp_rule.protocol = TCP_PROTOCOL_TXT
            tcp_match = tcp_rule.create_match('multiport')
            tcp_match.dports = ','.join(tcp_ports)
            tcp_target = tcp_rule.create_target('NFQUEUE')
            tcp_target.set_parameter('queue-num', '0')
            prerouting_chain.insert_rule(tcp_rule)

        # Rule to send all udp traffic for containers with matching ports to the NFQUEUE
        if udp_ports is not None:
            udp_rule = iptc.Rule()
            udp_rule.dst = crouter_network
            udp_rule.protocol = UDP_PROTOCOL_TXT
            udp_match = udp_rule.create_match('multiport')
            udp_match.dports = ','.join(udp_ports)
            udp_target = udp_rule.create_target('NFQUEUE')
            udp_target.set_parameter('queue-num', '0')
            prerouting_chain.insert_rule(udp_rule)

        # Rule to send all icmp traffic for containers to the NFQUEUE
        icmp_rule = iptc.Rule()
        icmp_rule.dst = crouter_network
        icmp_rule.protocol = 'icmp'
        icmp_target = icmp_rule.create_target('NFQUEUE')
        icmp_target.set_parameter('queue-num', '0')
        prerouting_chain.insert_rule(icmp_rule)

        # Rule to send all output packets from the proxy back to the NFQUEUE
        output_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), 'OUTPUT')

        port = self.config.router.proxy_port

        for rule in output_chain.rules:
            if rule.src == src and len(rule.matches) == 1 \
                    and rule.matches[0].parameters['sport'] == str(port) \
                    and rule.target.name == 'NFQUEUE':
                output_chain.delete_rule(rule)

        # Proxy rule for tcp
        proxy_rule = iptc.Rule()
        proxy_rule.src = crouter_network
        proxy_rule.protocol = TCP_PROTOCOL_TXT
        proxy_match = proxy_rule.create_match(TCP_PROTOCOL_TXT)
        proxy_match.sport = str(self.config.router.proxy_port)
        proxy_target = proxy_rule.create_target('NFQUEUE')
        proxy_target.set_parameter('queue-num', '0')
        output_chain.insert_rule(proxy_rule)

        # Proxy rule for udp
        proxy_rule = iptc.Rule()
        proxy_rule.src = crouter_network
        proxy_rule.protocol = UDP_PROTOCOL_TXT
        proxy_match = proxy_rule.create_match(UDP_PROTOCOL_TXT)
        proxy_match.sport = str(self.config.router.proxy_port)
        proxy_target = proxy_rule.create_target('NFQUEUE')
        proxy_target.set_parameter('queue-num', '0')
        output_chain.insert_rule(proxy_rule)

    def create_network(self, count):
        print('Creating network for {} hosts'.format(count), 'white')

        assert count > 0, 'Host count is 0'

        network_cfg = self.config.network
        client = docker.from_env()

        try:
            network = client.networks.get(network_cfg.name)
            network.remove()
        except docker.errors.NotFound:
            pass

        # Add three to the number of containers to account for the gateway, network, broadcast address
        subnet = utility.Net.generate_cidr(network_cfg.address, count + 3)

        ip = netaddr.IPNetwork(subnet)

        # Calc the gateway as network address + 1
        gateway = utility.Net.ipint_to_str(ip.first + 1)

        # Broadcast is the last
        broadcast = utility.Net.ipint_to_str(ip.last)

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
        print('Deleting containers', 'white')
        client = docker.from_env()
        containers = client.containers.list(all=True)

        # Remove the containers first
        for container in Container.select():
            print('Deleting {}'.format(container.name))
            for item in containers:
                if item.name == container.name:
                    item.remove(v=True, force=True)

        # Purge the db. Need to find a more efficient way
        # to do this
        for container in Container.select():
            container.delete_instance()

        for port in Port.select():
            port.delete_instance()

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

        print('Creating containers', 'white')

        # Create a unique list of host names
        naming = Naming()
        host_names = naming.generate_host_names(self.config.naming, count)

        for image in self.config.images:

            # If the image has no exposed ports then there is no use in
            # creating a container
            if image.name not in image_ports:
                continue

            ports = [port.text for port in image_ports[image.name]]

            for count in range(image.count):
                host_name = host_names.pop()
                ip = addresses.pop()
                mac = utility.Net.generate_mac(ip)
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
                new_container = Container.create(container_id=utility.Dictionary.get_attr(container, 'Id'),
                                                 name=host_name, ip=ip, mac=mac)
                for port in image_ports[image.name]:
                    Port.create(container=new_container.id, number=port.num, protocol=port.protocol)

        self.create_dnsmasq_conf()



