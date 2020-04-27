import asyncio
import logging
import socket
from collections import namedtuple

import netfilterqueue
from dpkt import icmp, ip

from utility import Net, get_key


class ContainerProxy:

    def __init__(self, container_mgr, endpoint, firewall, read_client=False):
        self.endpoint = endpoint
        self.container_mgr = container_mgr
        self.read_client = read_client
        self.firewall = firewall

    def start(self, loop):
        '''
        Starts the proxy server on the specified loop
        '''
        logging.info('Starting the container proxy server')
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # This option allows multiple processes to listen on the same port
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        server_socket.bind((self.endpoint.ip_str, self.endpoint.port))

        return asyncio.start_server(self.client_connected,
                                           sock=server_socket,
                                           loop=loop)

    async def proxy(self, reader, writer, start_data, container_name):
        '''
        Proxies data between the client connected to the proxy and the container
        specified by container name
        '''
        try:
            while True:
                if start_data is not None:
                    data = start_data
                    start_data = None
                else:
                    data = await reader.read(1024)
                    # Update last seen so that the idle monitor can determine
                    # if the container has not received network IO
                    await self.container_mgr.update_container(container_name)
                    if not data:
                        break
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
            # will be null
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
            client_addr = client_writer.get_extra_info('peername')
            ip = Net.ipstr_to_int(client_addr[0])
            key = get_key(client_addr[1], str(ip))
            container_addr = self.firewall.container_addrs[key]
            # Some TCP  discovery scanners will not send any data but SSH clients
            # send a client banner.
            if self.read_client:
                start_data = await client_reader.read(1024)
                await client_reader.drain()
        except ConnectionResetError:
            # Client sent a RST pkt no need to clean up writer
            return

        # If a scanner is doing a connect scan for discovery it will not send any
        # data. Setting read_client to true during a discovery scan will prevent
        # containers from starting up and overloading the system
        if self.read_client and (start_data is None or len(start_data) == 0):
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

        # If there was never a connection made the remote writer
        # will be null
        if not remote_writer is None:
            await self.close_stream_writer(remote_writer)
        await self.close_stream_writer(client_writer)
