import iptc
import logging
import netfilterqueue
import asyncio
import socket
from dpkt import ip, icmp
from utility import Net
from collections import namedtuple


HandlerResult = namedtuple('HandlerResult', 'modified, accept')


class NetworkHandler:

    def __init__(self, container_mgr, config):
        self.proxy_endpoint = EndPoint(
            config.router.get_interface_ip(), config.router.proxy_port)
        self.nfqueue = netfilterqueue.NetfilterQueue()
        self.queue_num = config.router.queue_num
        self.container_mgr = container_mgr
        self.nfq_socket = None
        self.icmp_handler = ICMPHandler(config)
        self.tcp_handler = TCPHandler(config, container_mgr)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def start(self):
        logging.info('Binding nfqueue')
        self.nfqueue.bind(int(self.queue_num), self.process_packet)
        self.nfq_socket = socket.fromfd(
            self.nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)

        loop = asyncio.get_event_loop()
        # Register the file descriptor for read event
        loop.add_reader(self.nfq_socket, self.reader)
        loop.run_forever()

    def stop(self):
        self.nfqueue.unbind()
        self.nfq_socket.close()
        self.icmp_handler.close()
        self.tcp_handler.close()

    def reader(self):
        self.nfqueue.get_packet(self.nfq_socket)

    def process_packet(self, pkt):
        ip_hdr = ip.IP(pkt.get_payload())
        dst_ip = Net.ipbytes_to_int(ip_hdr.dst)
        src_ip = Net.ipbytes_to_int(ip_hdr.src)

        logging.debug('Process_packet(tcp): %s:%s',
                      Net.ipint_to_str(src_ip), Net.ipint_to_str(dst_ip))

        result = None

        if ip_hdr.p == ip.IP_PROTO_ICMP:
            container = self.container_mgr.get_container_by_ip(dst_ip)
            if container is not None:
                result = self.icmp_handler.handle(
                    container, ip_hdr, ip_hdr.data)
                # ICMP requests are replied to by the handler so they will be dropped'
                pkt.drop()

        if ip_hdr.p == ip.IP_PROTO_TCP:
            tcp_hdr = ip_hdr.data
            result = self.tcp_handler.process(ip_hdr, tcp_hdr)

            if result.accept:
                if result.modified:
                    # Since the headers have been modified the chksums are
                    # cleared and are recalculated in bytes conversion by dpkt
                    ip_hdr.sum = 0
                    tcp_hdr.sum = 0
                    pkt.set_payload(bytes(ip_hdr))
                pkt.accept()
            else:
                pkt.drop()


class EndPoint:

    def __init__(self, ip_str, port):
        self.ip_str = ip_str
        self.ip_int = Net.ipstr_to_int(ip_str)
        self.ip_byte = Net.ipstr_to_bytes(ip_str)
        self.port = port


class TCPHandler:

    def __init__(self, config, container_mgr):
        self.config = config
        self.source_addrs = {}
        self.proxy_endpoint = EndPoint(
            config.router.get_interface_ip(), config.router.proxy_port)
        self.container_mgr = container_mgr

        loop = asyncio.get_event_loop()
        self.server = loop.run_until_complete(
            asyncio.start_server(self.client_connected,
                                 host=self.proxy_endpoint.ip_str,
                                 port=self.proxy_endpoint.port)
        )

    def close(self):
        self.server.stop()

    @staticmethod
    def get_key(port, ip):
        return ''.join([str(port), str(ip)])

    async def proxy(self, reader, writer, start_data, name):
        try:
            while True:
                if start_data is not None:
                    data = start_data
                    start_data = None
                else:
                    data = await reader.read(2048)
                    self.container_mgr.update_container(name)
                    if not data:
                        break
                writer.write(data)
                await writer.drain()
        except ConnectionResetError:
            logging.debug('proxy - connection reset')
            pass
        finally:
            writer.close()

    async def client_connected(self, client_reader, client_writer):

        start_data = None

        # Read a bit of data to see if this is just a scanner doing
        # a SYN scan. There is no need to start a container for this.
        try:
            client_addr = client_writer.get_extra_info('peername')
            ip = Net.ipstr_to_int(client_addr[0])
            key = self.get_key(client_addr[1], str(ip))
            container_addr = self.source_addrs[key]
            start_data = await client_reader.read(2048)
        except ConnectionResetError:
            client_writer.close()
            return

        # Discovery scans will not send any data
        if start_data is None or len(start_data) == 0:
            client_writer.close()
            return

        host = Net.ipbytes_to_int(container_addr[0])
        port = container_addr[1]

        # Start the container for the specified address
        name = await self.container_mgr.start_if_not_running(host, port, 6)

        if name is None:
            logging.debug('Unable to start %s', name)
            client_writer.close()
            return

        host = Net.ipint_to_str(host)

        # It might take a couple of tries to hit the container until it
        # fully spins up
        for retry in range(1, 5):
            try:
                logging.debug('Attempt %s to connect to %s %s:%s',
                              retry, name, host, port)
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    20
                )
                # Pass the initial data that was received above plus the container
                # name so that we know what container to update in the
                # container manager
                asyncio.ensure_future(self.proxy(
                    client_reader, remote_writer, start_data, name))
                asyncio.ensure_future(self.proxy(
                    remote_reader, client_writer, None, name))
                self.container_mgr.set_to_running(name)
                return
            except Exception as err:
                await asyncio.sleep(1)
                logging.error(err)
                continue

        client_writer.close()

    def process(self, ip_hdr, tcp_hdr):
        src_ip = Net.ipbytes_to_int(ip_hdr.src)
        dst_ip = Net.ipbytes_to_int(ip_hdr.dst)

        logging.debug('TCPHandler.process_packet(tcp): %s:%s -> %s:%s',
                      Net.ipint_to_str(src_ip), tcp_hdr.sport,
                      Net.ipint_to_str(dst_ip), tcp_hdr.dport)

        # Output data coming from the proxy
        if src_ip == self.proxy_endpoint.ip_int and tcp_hdr.sport == self.proxy_endpoint.port:
            key = self.get_key(tcp_hdr.dport, dst_ip)
            # Grab the addr of the docker container to modify
            # the outgoing packets to the original source
            src, sport = self.source_addrs.get(key, (None, None))
            if src is None or sport is None:
                logging.debug(
                    'Unable to find a source address for the key %s', key)
                return HandlerResult(False, False)
            else:
                ip_hdr.src = src
                tcp_hdr.sport = sport
                return HandlerResult(True, True)
        else:
            # See if there is a container registered to the specified dst and port
            container = self.container_mgr.get_container_by_endpoint(
                dst_ip, tcp_hdr.dport, 6)
            # Input data coming to the NFQUEUE
            # Only redirect to the proxy if this packet is for a container
            if container is not None:
                logging.debug(
                    'TCPHandler.process_packet(tcp): Found container %s', container.name)
                # Store the dst address of the docker container so that
                # outgoing packets can be modified with the correct
                # source addr above
                key = self.get_key(tcp_hdr.sport, src_ip)
                logging.debug(
                    'TCPHandler.process_packet(tcp): Using the key %s ', key)
                self.source_addrs[key] = (ip_hdr.dst, tcp_hdr.dport)
                # Modify the ip header so that the packet goes to the proxy server
                ip_hdr.dst = self.proxy_endpoint.ip_byte
                tcp_hdr.dport = self.proxy_endpoint.port
                return HandlerResult(True, True)
            else:
                logging.debug(
                    'TCPHandler.process_packet(tcp): Could not find a container')
                # This packet is not associated with a container so drop it
                # This should never happen unless the iptable rules are bad
                return HandlerResult(False, False)


class ICMPHandler:

    def __init__(self, config):
        self.icmp_client = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, ip.IP_PROTO_RAW)
        self.icmp_client.setblocking(False)
        self.icmp_client.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, True)

    def handle(self, container, ip_hdr, icmp_hdr):

        if icmp_hdr.type == icmp.ICMP_ECHO:
            src = ip_hdr.src
            dst = ip_hdr.dst
            org_dst_ip = Net.ipbytes_to_str(dst)
            dst_ip = Net.ipbytes_to_str(src)

            logging.debug('Echo request for %s %s', container.name, org_dst_ip)

            icmp_reply = ip_hdr
            icmp_reply.src = dst
            icmp_reply.dst = src
            icmp_reply.data.type = icmp.ICMP_ECHOREPLY
            # Setting the checksums to 0 allows them to be recalculated when
            # converted to bytes. Wireshark will not match up requests/reply if
            # checksums are foo'd'
            icmp_reply.data.sum = 0
            icmp_reply.sum = 0

            self.icmp_client.sendto(bytes(icmp_reply), (dst_ip, 1))
            return HandlerResult(True, False)

    def close(self):
        self.icmp_client.close()


class UDPHandler:

    def __init__(self, config, container_mgr):
        pass

    def process(self, ip_hdr, tcp_hdr):
        src_ip = Net.ipbytes_to_int(ip_hdr.src)
        dst_ip = Net.ipbytes_to_int(ip_hdr.dst)

        logging.debug('TCPHandler.process_packet(tcp): %s:%s -> %s:%s',
                      Net.ipint_to_str(src_ip), tcp_hdr.sport,
                      Net.ipint_to_str(dst_ip), tcp_hdr.dport)
