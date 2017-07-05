import ipaddress
import netaddr
from naming import Naming
import utility

import socket
import asyncio
import asyncdocker
from models import Container, Port
from collections import namedtuple
from datetime import datetime

ContainerUpdate = namedtuple('ContainerUpdate', 'name ip port')


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

    def __init__(self):

        self.client = asyncdocker.AsyncDocker()
        self.container_map = None
        self.containers = {}

    def start(self):
        self.container_map = self.__build_container_map()
        for port in self.container_map:
            print('{} containers for port {}'.format(len(self.container_map[port]), port))
        self.__stop_all_containers()

    async def monitor_idle_containers(self):
        while True:
            try:
                await asyncio.sleep(10)
                print('Checking for idle containers')
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
        print('{} is running'.format(name))
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
        port_map = self.container_map.get(port)
        if port_map is not None:
            name = port_map.get(ip)
            return name

    def __stop_all_containers(self):
        containers = Container.select()
        for container in containers:
            try:
                self.client.stop(container=container.name)
            except:
                pass

    def __build_container_map(self):

        container_map = {}

        end_points = Port.select(Port.value, Container.ip, Container.name)\
                         .join(Container)\
                         .order_by(Port.value)

        for end_point in end_points:
            port = end_point.value
            container = end_point.container
            if port not in container_map:
                container_map[port] = {}
            ip = utility.IPAddress.str_to_int(container.ip)
            container_map[port][ip] = container.name

        return container_map
'''
    def pull_images(self, host_defs_cfg):
        # Pull down images defined in the host defs if they are
        # not already present on the local system
        for host_def in host_defs_cfg:
            self.client.pull(host_def.image)

    def generate_mac(self, ip):
        mac = '02:42'
        for octet in ip.split('.'):
            mac += ':{:02x}'.format(int(octet))
        return mac

    def create_containers(self, host_defs_cfg, naming_cfg):
        Container.delete()

        # Make sure the defined images are available
        self.pull_images(host_defs_cfg)

        # Determine how many containers need to be created in order to
        # get a list of host names
        count = sum([host_def.count for host_def in host_defs_cfg])

        # Create a unique list of host names
        naming = Naming()
        host_names = naming.generate_host_names(naming_cfg, count)

        for host_def in host_defs_cfg:

            # Determine the ip range in order to specify a valid ip
            # address for each container
            network = self.client.inspect_network(host_def.network)
            subnet = network['IPAM']['Config'][0]['Subnet']
            ip_range = list(netaddr.IPSet([subnet, ]))
            ip_range.reverse()

            for count in range(host_def.count):
                host_name = host_names.pop()
                ip = str(ip_range.pop())
                mac = self.generate_mac(ip)
                endpoint_config = self.client.create_endpoint_config(ipv4_address=ip)
                networking_config = self.client.create_networking_config({host_def.network : endpoint_config})
                container_id = self.client.create_container(image=host_def.image,
                                                         detach=True,
                                                         hostname=host_name,
                                                         name=host_name,
                                                         ports=host_def.ports,
                                                         networking_config=networking_config,
                                                         mac_address=mac)

                container = self.client.inspect_container(container_id)
                # Persist the container info to the db with the ports
                # Ports are used to determine what listeners to create
                new_container = Container.create(container_id=container["Id"],
                                                 name=host_name, ip=ip, mac=mac)
                for port in host_def.ports:
                    Port.create(container=new_container.id, value=port)
'''



