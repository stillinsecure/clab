import asyncio
import logging
import socket
from collections import namedtuple

import netfilterqueue
from dpkt import icmp, ip
from netfilter import TCPEndPoint
from utility import Net


class ContainerProxy:

    def __init__(self, container_mgr, config):         
        self.endpoint = TCPEndPoint(config.firewall.get_interface_ip(), config.firewall.proxy_port)
        self.container_mgr = container_mgr
        self.config = config

    def start(self, loop):
        '''
        Starts the proxy server on the specified loop
        '''
        logging.info('Starting the container proxy server')
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('0.0.0.0', self.endpoint.port))
        return asyncio.start_server(self.client_connected,
                                           sock=server_socket,
                                           loop=loop)

    async def proxy(self, reader, writer, start_data, container_name):
        '''
        Proxies data between the client connected to the proxy and the container
        specified by container name
        '''
        read_buffer = self.config.firewall.read_buffer

        try:
            while True:
                if start_data is not None:
                    data = start_data
                    start_data = None
                else:
                    data = await reader.read(read_buffer)
                    if not data:
                        break
                    # Update last seen so that the idle monitor can determine
                    # if the container has not received network IO
                    await self.container_mgr.update_container(container_name)
                    writer.write(data)
                    await writer.drain()
        except ConnectionResetError:
            logging.debug('Connection reset writer %s', container_name)
        except Exception as ex:
            logging.error('proxy - %s', ex)
        finally:
           await self.close_stream_writer(writer)

    async def close_stream_writer(self, writer):
        ''' 
        Safely closes the specified stream writer
        '''
        try:
            # If the call to open_connection failed, the writer
            # will be null1
            if not writer is None:
                writer.close()
                await writer.wait_closed()
        except Exception as ex:
            # Most likely connection reset from client sending a RST
            logging.debug('Closing writer %s', ex)

    async def client_connected(self, client_reader, client_writer):

        start_data = None
        remote_writer = None
        
        # Retina discovery scan sends 0 bytes and will make it past the read
        # below and start a container. Could be to read the banner

        # Responds to scans without starting a container

        #   nmap SYN will not get in here.
        #   OS responds with RST packet

        # - nmap ping scan will be handled by ICMP handler
        #   nmap -sn

        # - nmap connect scan will throw a connection reset error on the start data read after
        #   it sends a RST packet
        #   nmap -sT

        # - nmap SYN, NULL, FIN, XMAS scan will not get here but will show up in NFQUEUE
        #   nmap -sS, nmap -sN, nmap -sF, nmap -sX. No packets will be sent in response

        # - nmap ACK,WINDOW, Maimom scan will not get in here but OS will send RST packet
        #   nmap -sA, nmap -sW, nmap -sM

        # Read a bit of data to see if this is just a scanner
        try:
            source_addr = client_writer.get_extra_info('peername')
            source_ip = Net.ipstr_to_int(source_addr[0])
            source_port = source_addr[1]
            container_addr = self.container_mgr.connections.get(source_ip, source_port)
            # This can happen if someone tries to connect directly to tcp:5996
            if container_addr is None:
                await self.close_stream_writer(client_writer)
                return

            # Some TCP  discovery scanners will not send any data but SSH clients
            # send a client banner.
            if self.config.firewall.read_client:
                start_data = await client_reader.read(self.config.firewall.read_buffer)
                await client_reader.drain()
        except ConnectionResetError:
            # Client sent a RST pkt no need to clean up writer
            return

        # If a scanner is doing a connect scan for discovery it will not send any
        # data. Setting read_client to true during a discovery scan will prevent
        # containers from starting up and overloading the system
        if self.config.firewall.read_client and (start_data is None or len(start_data) == 0):
            await self.close_stream_writer(client_writer)
            return

        start_data = None
        host = container_addr[0]
        port = container_addr[1]

        # Start the container for the specified address
        container = await self.container_mgr.start_if_not_running(host, port, 6)

        if container is None:
            await self.close_stream_writer(client_writer)
            return

        host = Net.ipint_to_str(host)

        # It might take a couple of tries to hit the container until it
        # fully spins up
        for retry in range(1, container.start_retry_count):
            try:
                logging.debug('Attempt %s to connect to %s %s:%s',
                              retry, container.name, host, port)
                remote_reader, remote_writer = await asyncio.open_connection(host, port)
            except Exception as err:
                await asyncio.sleep(container.start_delay)
                logging.debug(err)
                continue

            # Pass the initial data that was received above plus the container
            # name so that we know what container to update in the
            # container manager
            asyncio.ensure_future(self.proxy(
                client_reader, remote_writer, start_data, container.name))
            asyncio.ensure_future(self.proxy(
                remote_reader, client_writer, None, container.name))
            return

        # If there was never a connection made the and remote writer
        # will be null
        if not remote_writer is None:
            await self.close_stream_writer(remote_writer)

        await self.close_stream_writer(client_writer)
