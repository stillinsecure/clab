import aiohttp
import os
import json
import asyncio
import logging
import re
from collections import namedtuple
from datetime import datetime

import aiodocker
import netaddr

import utility
from models import Container, Port
from naming import Naming
from netfilter import (TCP_PROTOCOL, TCP_PROTOCOL_TXT, UDP_PROTOCOL,
                       UDP_PROTOCOL_TXT, IPTableRules)
from utility import Dictionary

ContainerUpdate = namedtuple('ContainerUpdate', 'name ip port')
ExposedPort = namedtuple('ExposedPort', 'num text protocol')

CONTAINER_STARTED = 1
CONTAINER_STOPPED = 3
SCRIPTS_DIR = '/scripts'


class ProxiedContainer(object):
    running_containers = 0

    def __init__(self, container):
        self.last_seen = datetime.now()
        self.container_id = container.container_id
        self.name = container.name
        self.status = CONTAINER_STOPPED
        self.event = asyncio.Event()

    async def start_container_if_not_running(self, pool):
        '''
        The aiodocker lib requires that the container be loaded and then started. This
        requires two calls to the API. This call allows the container to be started in
        one call to the API
        '''
        client = None

        try:
            client = await pool.get()
            async with client._query('containers/{}/start'.format(self.container_id),
                                     method='POST',
                                     headers={'content-type': 'application/json'}) as response:
                if response.status == 204 or response.status == 304:
                    if response.status == 304:
                        logging.debug(
                            '%s container is already running', self.name)
                    else:
                        logging.debug('Container %s is running', self.name)
                    self.status = CONTAINER_STARTED
                else:
                    logging.error(
                        'Unable to start the container %s %s', self.name, response.status)
        except Exception as ex:
            logging.error(ex)
        finally:
            if not client is None:
                pool.put_nowait(client)

    async def stop_container(self, pool):
        '''
        The aiodocker lib requires that the container be loaded and then stopped. This
        requires two calls to the API. This call allows the container to be stopped in
        one call to the API
        '''
        client = None
        try:
            client = await pool.get()
            async with client._query("containers/{}/stop".format(self.container_id),
                                     method="POST") as response:
                if response.status == 204 or response.status == 304:
                    if response.status == 304:
                        logging.debug(
                            '%s container is already stopped', self.name)
                    self.status = CONTAINER_STOPPED
                else:
                    logging.error('Unable to stop the container %s %s',
                                  self.name, response.status)
        except Exception as ex:
            logging.error(ex)
        finally:
            if not client is None:
                pool.put_nowait(client)


class ContainerConnectionMapping:

    def __init__(self):
        self.connection_maps = {}
        self.connections_made = 0

    def add(self, source_ip, source_port, dest_ip, dest_port):

        key = self.__get_key(source_ip, source_port)
        self.connection_maps[key] = (dest_ip, dest_port)

    def get(self, source_ip, source_port):
        self.connections_made = self.connections_made + 1

        key = self.__get_key(source_ip, source_port)
        if key in self.connection_maps:
            connection_mapping = self.connection_maps[key]
            del self.connection_maps[key]
            return connection_mapping
        else:
            ip = utility.Net.ipint_to_str(source_ip)
            logging.error(
                'Unable to find a container connection for %s %s', ip, source_port)
            return None

    def __get_key(self, port, ip):
        return ''.join([str(port), str(ip)])


class ContainerManager:

    EndPoint = namedtuple('EndPoint', 'port ip container_name')

    def __init__(self, config):
        self.client_pool = asyncio.Queue(config.container_manager.client_pool)
        self.container_map_by_port = None
        self.container_map_by_ip = None
        self.container_map_by_name = None
        self.containers = {}
        self.config = config
        self.idle_monitor_task = None
        self.connections = ContainerConnectionMapping()
        self.running_containers = 0
        self.container_map_by_port, self.container_map_by_ip, self.container_map_by_name = self.build_container_map()

    async def start(self, create_pool=True):
        '''
        Loads the containers into dictionaries for fast retrieval
        '''
        logging.info('Starting container manager')

        for _ in range(self.config.container_manager.client_pool):
            await self.client_pool.put(aiodocker.Docker())

    async def stop(self):
        '''
        Closes the docker API clients in the pool
        '''
        logging.info('Stopping container manager')
        count = self.client_pool.maxsize

        for _ in range(1, count):
            client = await self.client_pool.get()
            await client.close()

    async def monitor_idle_containers(self):

        logging.debug('Starting idle container monitor')

        poll_time = self.config.container_manager.poll_time
        expire_after = self.config.container_manager.expire_after

        while 1:
            try:
                await asyncio.sleep(poll_time)
                stopped = 0
                logging.info('%s running containers', self.running_containers)
                for key, container in list(self.containers.items()):
                    if container.status == CONTAINER_STARTED:
                        last_seen = (datetime.now() -
                                     container.last_seen).total_seconds()
                        if last_seen >= expire_after:
                            try:
                                # Don't let the container be started or stopped by another
                                # task while trying to stop.
                                container.event.clear()
                                await container.stop_container(self.client_pool)
                                if container.status == CONTAINER_STOPPED:
                                    del self.containers[key]
                                    self.running_containers = self.running_containers - 1
                            finally:
                                container.event.set()
                        stopped = stopped + 1
                    # Limit the number of containers stopped per iteration of the idle monitor
                    # loop
                    if stopped == self.config.container_manager.stop_per_iteration:
                        break

                if self.running_containers == 0:
                    logging.info(
                        'Stopping container monitor, there are no containers to monitor')
                    return

            except Exception as ex:
                logging.error(ex)

    async def start_if_not_running(self, ip, port, protocol):
        logging.debug('Connection request %s %s', ip, port)

        container = self.get_container_by_endpoint(ip, port, protocol)

        if container is None:
            return None

        if not container.name in self.containers:
            running_container = ProxiedContainer(container)
        else:
            running_container = self.containers[container.name]
            # Wait until a stop or start is done with this container
            # by another task
            await running_container.event.wait()

        if running_container.status == CONTAINER_STOPPED:
            # Block anyone trying to do anything with this container
            try:
                # Put the running container object in the collection so that
                # another task that tries to start the same container will
                # wait. It goes in as stopped but will change to started when
                # finished. If the container fails to start it will be stopped
                # and the new task waiting will try to start it
                self.containers[container.name] = running_container
                running_container.event.clear()
                await running_container.start_container_if_not_running(self.client_pool)
                if running_container.status == CONTAINER_STOPPED:
                    del self.containers[container.name]
                else:
                    self.running_containers = self.running_containers + 1
            finally:
                # Let someone do something with this container
                running_container.event.set()

            # Start monitoring for idle containers since there is at least one
            # running now
            if self.idle_monitor_task is None or self.idle_monitor_task.done():
                self.idle_monitor_task = asyncio.ensure_future(
                    self.monitor_idle_containers())
        else:
            logging.debug('Container is %s already running %s',
                          container.name, running_container.status)
            assert running_container.status == CONTAINER_STARTED
            self.containers[container.name].last_seen = datetime.now()

        return container

    async def update_container(self, container_name):
        '''
        Updates the running container by name
        '''
        if container_name in self.containers:
            self.containers[container_name].last_seen = datetime.now()

    def get_port_map_key(self, port, protocol):
        return int(''.join([str(protocol), str(port)]))

    def get_container_by_name(self, name):
        '''
        Indexed lookup to retrieve container by name
        '''
        if name in self.container_map_by_name:
            return self.container_map_by_name[name]

    def get_container_by_endpoint(self, ip, port, protocol):
        '''
        Indexed lookup to retrieve containers by ip, port, and protocol
        '''
        port_map_key = self.get_port_map_key(port, protocol)
        port_map = self.container_map_by_port.get(port_map_key)
        if port_map is not None:
            container = port_map.get(ip)
            return container

    def get_container_by_ip(self, ip):
        '''
        Indexed lookup to retrieve containers by ip
        '''
        if ip in self.container_map_by_ip:
            return self.container_map_by_ip[ip]
        return None

    async def stop_all_containers(self):
        containers = Container.select()
        client = await self.client_pool.get()
        for container in containers:
            try:
                client.stop(container=container.name)
            except:
                pass

    def build_container_map(self):
        '''
        Creates dictionaries for fast retrieval of container information by index.
        '''

        container_map_by_port = {}
        container_map_by_ip = {}
        container_map_by_name = {}

        containers = Container.select()
        for container in containers:
            container_map_by_name[container.name] = container

        end_points = Port.select(Port.number, Port.protocol, Container.ip, Container.name,
                                 Container.container_id, Container.start_delay, Container.start_retry_count,
                                 Container.start_on_create, Container.sub_domain) \
            .join(Container)\
            .order_by(Port.number)

        for end_point in end_points:
            port_key = self.get_port_map_key(
                end_point.number, end_point.protocol)
            container = end_point.container

            if port_key not in container_map_by_port:
                container_map_by_port[port_key] = {}

            ip = utility.Net.ipstr_to_int(container.ip)
            container_map_by_port[port_key][ip] = container

            if ip not in container_map_by_ip:
                container_map_by_ip[ip] = container

        return container_map_by_port, container_map_by_ip, container_map_by_name


class ContainerBuilder:

    def __init__(self, config):
        self.config = config

    def view(self, container_map_by_port=None, container_map_by_ip=None):
        '''
        Displays the created containers specified by the current configuration
        '''
        containers = Container.select()
        for container in containers:
            print('{}.{}.{}\t\t{}'.format(container.name,
                                          container.sub_domain, self.config.network.domain, container.ip))

    async def pull_image(self, image_name, existing_images):
        '''
        Pulls the image down if it is not already on disk
        '''
        image_to_pull = None

        if len(existing_images) == 0:
            image_to_pull = image_name
        else:
            for existing_image in existing_images:
                if not image_name in existing_image['RepoTags']:
                    image_to_pull = image_name
                else:
                    image_to_pull = None
                    break

        if not image_to_pull is None:
            client = aiodocker.Docker()
            logging.debug('Pulling down the image %s', image_name)
            await client.images.pull(image_name)
            await client.close()

    async def setup_images(self, images_cfg, update):

        logging.info('Setting up images')

        count = 0
        image_ports = {}
        unique_ports = {}

        client = aiodocker.Docker()

        existing_images = await client.images.list()

        # If updating an existing deployment then create a list of
        # existing ports
        if update:
            existing_ports = Port.select(Port.number).distinct()

            for existing_port in existing_ports:
                port = ExposedPort(
                    existing_port.number, '{}/tcp'.format(existing_port.number), TCP_PROTOCOL)
                unique_ports[existing_port.number] = port

        # Pull down images defined in the images if they are
        # not already present on the local system
        for image_cfg in images_cfg:

            # Pull down the image if it is not already on the system
            await self.pull_image(image_cfg.name, existing_images)

            image = await client.images.inspect(image_cfg.name)

            if Dictionary.has_attr(image, 'ContainerConfig', 'ExposedPorts'):
                count += image_cfg.count
                exposed_ports = list(
                    image['ContainerConfig']['ExposedPorts'])

                for exposed_port in exposed_ports:
                    match = re.search('(\d+)\/(tcp|udp)', exposed_port)

                    if match is not None:
                        port_num = int(match.group(1))
                        protocol = match.group(2)

                        if protocol == TCP_PROTOCOL_TXT:
                            protocol = TCP_PROTOCOL
                        elif protocol == UDP_PROTOCOL_TXT:
                            protocol = UDP_PROTOCOL

                        port = ExposedPort(
                            port_num, exposed_port, protocol)

                        if image_cfg.name not in image_ports:
                            image_ports[image_cfg.name] = []
                        image_ports[image_cfg.name].append(port)

                        if port_num not in unique_ports:
                            unique_ports[port_num] = port

        await client.close()
        return count, image_ports, unique_ports.values()

    async def create_network(self, count, subnet, gateway):
        '''
        Creates a docker network with a subnet to match the number of
        containers specified by count
        '''
        client = aiodocker.Docker()

        network_cfg = self.config.network
        logging.info('Creating network %s for %s hosts',
                     network_cfg.name, count)

        try:
            logging.debug('Removing docker network %s', network_cfg.name)
            network = await client.networks.get(network_cfg.name)
            await network.delete()
        except aiodocker.DockerError:
            pass

     


        # default is bridge
        config = {'Name': network_cfg.name, 'IPAM': {
                  'Driver': 'default',
                  'Config': [
                      {
                          'Subnet': subnet,
                          'Gateway': gateway
                      }
                  ]
                  },
                  }

        network = await client.networks.create(config)
        logging.info('Created network %s %s', network_cfg.name, subnet)            
        await client.close()

    async def delete_containers(self):
        '''
        Deletes the containers in docker and the db records
        '''
        logging.info('Deleting containers')

        client = aiodocker.Docker()

        containers = await client.containers.list(all=True)
        # Remove the containers first
        for container in Container.select():
            logging.debug('Deleting %s', container.name)
            for item in containers:
                if item.id == container.container_id:
                    await item.delete(v=True, force=True)

        # Purge the db. Need to find a more efficient way
        # to do this
        for container in Container.select():
            container.delete_instance()

        for port in Port.select():
            port.delete_instance()

        await client.close()

    def get_available_address(self, count):
        # Add three to the number of containers to account for the gateway,
        # network, broadcast address
        subnet = utility.Net.generate_cidr(self.config.network.address, count + 3)

        ip = netaddr.IPNetwork(subnet)

        # Calc the gateway as network address + 1
        gateway = utility.Net.ipint_to_str(ip.first + 1)

        # Broadcast is the last
        broadcast = utility.Net.ipint_to_str(ip.last)

        addresses = [str(address)
                     for address in list(netaddr.IPSet([subnet, ]))]

        if gateway in addresses:
            addresses.remove(gateway)
        if broadcast in addresses:
            addresses.remove(broadcast)
        if self.config.network.address in addresses:
            addresses.remove(self.config.network.address)

        # Remove existing addresses
        for container in Container.select(Container.ip):
            addresses.remove(container.ip)

        return addresses, subnet, gateway

    async def create_containers(self, update):
        # Clean up all the containers
        if not update:
            await self.delete_containers()

        # Make sure the defined images are available and config the ports
        count, image_ports, unique_ports = await self.setup_images(self.config.images, update)

        addresses, subnet, gateway = self.get_available_address(self.config.network.hosts)

        # Do not recreate the network during an update. docker does not provide a 
        # way to update the network so during an update it would need to be dropped and
        # updated. The network id for any existing containers would need to be updated
        if not update:
            # Create a network for the containers
            await self.create_network(self.config.network.hosts, subnet, gateway)

            # Apply the iptable rules required for the configured images
            rules = IPTableRules(self.config)
            rules.create(subnet, unique_ports)

       
        logging.info('Creating containers')

        # Create a unique list of host names
        naming = Naming()
        host_names = naming.generate_host_names(self.config.naming, count)

        scripts_dir = ''.join([os.getcwd(), SCRIPTS_DIR])
        logging.info('Using %s for script directory', scripts_dir)

        client = aiodocker.Docker()
        for image in self.config.images:

            # If the image has no exposed ports then there is no use in
            # creating a container
            if image.name not in image_ports:
                continue

            ports = [port.text for port in image_ports[image.name]]
            ports = dict.fromkeys(ports, {})
            for count in range(image.count):
                host_name = host_names.pop()
                ip = addresses.pop(0)
                mac = utility.Net.generate_mac(ip)
                config = {'Hostname': host_name,
                          'Image': image.name,
                          'ExposedPorts': ports,
                          'MacAddress': mac,
                          'Env': image.env_variables,
                          'NetworkingConfig': {
                              'EndpointsConfig': {
                                  'clab': {
                                      'IPAMConfig': {
                                          'IPv4Address': ip,
                                    },
                                }
                            }
                        }
                }

                if not image.startup_script is None and len(image.startup_script) > 0:
                    config['HostConfig'] = {
                              'Binds': ['{}:{}'.format(scripts_dir, SCRIPTS_DIR)
                              ],
                          }

                logging.debug('Creating container %s:%s',
                              host_name, image.name)
                container=await client.containers.create(config, name = host_name)

                # Persist the container info to the db with the ports
                # Ports are used to determine what listeners to create
                new_container=Container.create(container_id = container.id,
                                                 name = host_name, ip = ip, mac = mac,
                                                 start_delay = image.start_delay,
                                                 start_retry_count = image.start_retry_count,
                                                 start_on_create = image.start_on_create,
                                                 sub_domain = image.sub_domain)

                # Some containers perform a lot of startup work when run for the first time
                # To mitigate this containers can be started and stopped on creation
                if image.start_on_create:
                    await self.start_container_on_create(image, new_container, client)

                for port in image_ports[image.name]:
                    Port.create(container = new_container.id,
                                number=port.num, protocol=port.protocol)

        await client.close()

    async def start_container_on_create(self, image, container, client):
        '''
        Starts the container when it is created and optionally runs startup
        scripts. Some containers such as mysql create the db on first start so
        this option allows this initialization to occur before the proxy tries
        to connect to the container.
        '''
        container = await client.containers.get(container.container_id)
        await container.start()

        if not image.startup_script is None and len(image.startup_script) > 0:
            script = ''.join([SCRIPTS_DIR, '/', image.startup_script])
            execute_script = await container.exec(script, workdir=SCRIPTS_DIR)
            stream = execute_script.start(detach=False)
            while 1:
                try:
                    result = await stream.read_out()
                    logging.debug(result)
                except aiohttp.streams.EofStream:
                    break
            await stream.close()

        await container.stop()
