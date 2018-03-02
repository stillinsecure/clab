
import re
import netaddr
from utility import Dictionary
import utility
import asyncio
import asyncdocker
import docker
import logging
from naming import Naming
from models import Container, Port
from collections import namedtuple
from datetime import datetime
from network import IPTableRules, TCP_PROTOCOL_TXT, TCP_PROTOCOL, UDP_PROTOCOL_TXT, UDP_PROTOCOL

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
                    if last_seen > 10:
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
        if container.name not in self.containers:
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
                rev_ip = '.'.join(reversed(container.ip.split('.')))
                fqdn = '{}.{}'.format(container.name, self.config.network.domain)
                record = 'address=/{}/{}\r\n'.format(fqdn, container.ip)
                ptr = ''.join(['ptr-record=', rev_ip, '.in-addr.arpa,', fqdn, '\r\n'])
                f.write(record)
                f.write(ptr)

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
            addresses.remove(network_cfg.address)

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
        rules = IPTableRules(self.config)
        rules.create(subnet, unique_ports)

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



