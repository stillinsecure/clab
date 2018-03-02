import iptc
import logging
import netfilterqueue
import asyncio
import socket
from dpkt import ip, icmp
from utility import Net
from collections import namedtuple


HandlerResult = namedtuple('HandlerResult', 'modified, accept')

CIENT_TO_CONTAINER_DIR = 1
CONTAINER_TO_CLIENT_DIR = 2

IPTABLES_NFQUEUE = 'NFQUEUE'
IPTABLES_QUEUE_NUM = 'queue-num'
IPTABLES_MULTIPORT = 'multiport'
IPTABLES_PREROUTING = 'PREROUTING'
IPTABLES_OUTPUT = 'OUTPUT'

TCP_PROTOCOL_TXT = 'tcp'
UDP_PROTOCOL_TXT = 'udp'
ICMP_PROTOCOL_TXT = 'icmp'

TCP_PROTOCOL = 6
UDP_PROTOCOL = 17


class IPTableRules:

    def __init__(self, config):
        self.config = config

    def delete_clab_chain(self):
        prerouting_chain = iptc.Chain(iptc.Table(iptc.Table.MANGLE), IPTABLES_PREROUTING)

        for index in range(len(prerouting_chain.rules), 0, -1):
            rule = prerouting_chain.rules[index-1]
            if rule.target.name == self.config.router.chain_name:
                prerouting_chain.delete_rule(rule)

        output_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), IPTABLES_OUTPUT)

        for index in range(len(output_chain.rules), 0, -1):
            rule = output_chain.rules[index-1]
            if rule.target.name == self.config.router.chain_name:
                output_chain.delete_rule(rule)

        self.delete_chain(iptc.Table.MANGLE, self.config.router.chain_name)
        self.delete_chain(iptc.Table.FILTER, self.config.router.chain_name)

    def delete_chain(self, table_name, chain_name):
        table = iptc.Table(table_name)
        for table_index in range(len(table.chains), 0, -1):
            chain = table.chains[table_index-1]
            if chain.name == chain_name:
                for chain_index in range(len(chain.rules), 0, -1):
                    rule = chain.rules[chain_index-1]
                    chain.delete_rule(rule)
                table.delete_chain(chain)
                return

    def create(self, clab_network, ports):
        print('Setting up iptables', 'white')

        assert clab_network is not None and len(clab_network) > 1, 'A network address is required'
        assert ports is not None and len(ports) >= 1, 'Images need to be configured with TCP ports'

        proxy_port = self.config.router.proxy_port

        self.delete_clab_chain()

        # Create a new CLAB chain in the MANGLE and FILTER tables
        # to make it easier to manage the rules, ie drop the rules
        # on every run
        mangle_table = iptc.Table(iptc.Table.MANGLE)
        mangle_clab_chain = mangle_table.create_chain(self.config.router.chain_name)

        filter_table = iptc.Table(iptc.Table.FILTER)
        output_clab_chain = filter_table.create_chain(self.config.router.chain_name)

        tcp_ports = [str(port.num) for port in ports if port.protocol == TCP_PROTOCOL]
        udp_ports = [str(port.num) for port in ports if port.protocol == UDP_PROTOCOL]

        # Rule to send all tcp traffic for containers with matching ports to the NFQUEUE
        if tcp_ports is not None and len(tcp_ports) > 0:
            tcp_rule = iptc.Rule()
            tcp_rule.dst = clab_network
            tcp_rule.protocol = TCP_PROTOCOL_TXT
            tcp_match = tcp_rule.create_match(IPTABLES_MULTIPORT)
            tcp_match.dports = ','.join(tcp_ports)
            tcp_target = tcp_rule.create_target(IPTABLES_NFQUEUE)
            tcp_target.set_parameter(IPTABLES_QUEUE_NUM, self.config.router.queue_num)
            mangle_clab_chain.insert_rule(tcp_rule)

        # Rule to send all udp traffic for containers with matching ports to the NFQUEUE
        if udp_ports is not None and len(udp_ports) > 0:
            udp_rule = iptc.Rule()
            udp_rule.dst = clab_network
            udp_rule.protocol = UDP_PROTOCOL_TXT
            udp_match = udp_rule.create_match(IPTABLES_MULTIPORT)
            udp_match.dports = ','.join(udp_ports)
            udp_target = udp_rule.create_target(IPTABLES_NFQUEUE)
            udp_target.set_parameter(IPTABLES_QUEUE_NUM, self.config.router.queue_num)
            mangle_clab_chain.insert_rule(udp_rule)

        # Rule to send all icmp traffic for containers to the NFQUEUE
        icmp_rule = iptc.Rule()
        icmp_rule.dst = clab_network
        icmp_rule.protocol = ICMP_PROTOCOL_TXT
        icmp_target = icmp_rule.create_target(IPTABLES_NFQUEUE)
        icmp_target.set_parameter(IPTABLES_QUEUE_NUM, self.config.router.queue_num)
        mangle_clab_chain.insert_rule(icmp_rule)

        # Rule to send all output packets from the proxy back to the NFQUEUE
        # Proxy rule for tcp
        proxy_rule = iptc.Rule()
        proxy_rule.protocol = TCP_PROTOCOL_TXT
        proxy_match = proxy_rule.create_match(TCP_PROTOCOL_TXT)
        proxy_match.sport = str(proxy_port)
        proxy_target = proxy_rule.create_target(IPTABLES_NFQUEUE)
        proxy_target.set_parameter(IPTABLES_QUEUE_NUM, self.config.router.queue_num)
        output_clab_chain.insert_rule(proxy_rule)

        # Create RULES to send traffic to the CLAB chain
        prerouting_chain = iptc.Chain(iptc.Table(iptc.Table.MANGLE), IPTABLES_PREROUTING)
        prerouting_rule = iptc.Rule()
        prerouting_rule.create_target(self.config.router.chain_name)
        prerouting_chain.insert_rule(prerouting_rule)

        output_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), IPTABLES_OUTPUT)
        output_rule = iptc.Rule()
        output_rule.create_target(self.config.router.chain_name)
        output_chain.insert_rule(output_rule)


class UDPHandler:

    def __init__(self, config, container_mgr):
        pass

    def process(self, ip_hdr, tcp_hdr):
        src_ip = Net.ipbytes_to_int(ip_hdr.src)
        dst_ip = Net.ipbytes_to_int(ip_hdr.dst)

        logging.debug('TCPHandler.process_packet(tcp): %s:%s -> %s:%s',
                      Net.ipint_to_str(src_ip), tcp_hdr.sport,
                      Net.ipint_to_str(dst_ip), tcp_hdr.dport)


class TCPHandler:

    def __init__(self, config, container_mgr):
        self.config = config
        self.source_addrs = {}
        self.proxy_endpoint = EndPoint(config.router.get_interface_ip(), config.router.proxy_port)
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
                        print('No data')
                        break
                writer.write(data)
                await writer.drain()
        except ConnectionResetError:
            print('connection reset')
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
            print('Unable to start {}'.format(name))
            client_writer.close()
            return

        host = Net.ipint_to_str(host)

        # It might take a couple of tries to hit the container until it
        # fully spins up
        for retry in range(1, 5):
            try:
                logging.debug('Attempt %s to connect to %s %s:%s', retry, name, host, port)
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    20
                )
                # Pass the initial data that was received above plus the container
                # name so that we know what container to update in the
                # container manager
                asyncio.ensure_future(self.proxy(client_reader, remote_writer, start_data, name))
                asyncio.ensure_future(self.proxy(remote_reader, client_writer, None, name))
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
                logging.debug('Unable to find a source address for the key %s', key)
                return HandlerResult(False, False)
            else:
                ip_hdr.src = src
                tcp_hdr.sport = sport
                return HandlerResult(True, True)
        else:
            # See if there is a container registered to the specified dst and port
            container = self.container_mgr.get_container_by_endpoint(dst_ip, tcp_hdr.dport, 6)
            # Input data coming to the NFQUEUE
            # Only redirect to the proxy if this packet is for a container
            if container is not None:
                logging.debug('TCPHandler.process_packet(tcp): Found container %s', container.name)
                # Store the dst address of the docker container so that
                # outgoing packets can be modified with the correct
                # source addr above
                key = self.get_key(tcp_hdr.sport, src_ip)
                logging.debug('TCPHandler.process_packet(tcp): Using the key %s ', key )
                self.source_addrs[key] = (ip_hdr.dst, tcp_hdr.dport)
                # Modify the ip header so that the packet goes to the proxy server
                ip_hdr.dst = self.proxy_endpoint.ip_byte
                tcp_hdr.dport = self.proxy_endpoint.port
                return HandlerResult(True, True)
            else:
                logging.debug('TCPHandler.process_packet(tcp): Could not find a container')
                # This packet is not associated with a container so drop it
                # This should never happen unless the iptable rules are bad
                return HandlerResult(False, False)


class ICMPHandler:

    def __init__(self, config):
        self.icmp_client = socket.socket(socket.AF_INET, socket.SOCK_RAW, ip.IP_PROTO_RAW)
        self.icmp_client.setblocking(False)
        self.icmp_client.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, True)

    def handle(self, container, ip_hdr, icmp_hdr):

        if icmp_hdr.type == icmp.ICMP_ECHO:
            src = ip_hdr.src
            dst = ip_hdr.dst
            org_dst_ip = Net.ipbytes_to_str(dst)
            dst_ip = Net.ipbytes_to_str(src)

            logging.debug('Echo request for %s %s', container.name, org_dst_ip )

            icmp_reply = ip_hdr
            icmp_reply.src = dst
            icmp_reply.dst = src
            icmp_reply.data.type = icmp.ICMP_ECHOREPLY
            # Setting the checksums to 0 allows them to be recalculated when
            # converted to bytes. Wireshark will not match up requests/reply if
            # checksums are foo'd'
            icmp_reply.data.sum = 0
            icmp_reply.sum = 0

            self.icmp_client.sendto(bytes(icmp_reply),(dst_ip, 1))
            return HandlerResult(True, False)

    def close(self):
        self.icmp_client.close()


class EndPoint:

    def __init__(self, ip_str, port):
        self.ip_str = ip_str
        self.ip_int = Net.ipstr_to_int(ip_str)
        self.ip_byte = Net.ipstr_to_bytes(ip_str)
        self.port = port


class NetworkHandler:

    def __init__(self, container_mgr, config):
        self.proxy_endpoint = EndPoint(config.router.get_interface_ip(), config.router.proxy_port)
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
        self.nfqueue.bind(self.queue_num, self.process_packet)
        self.nfq_socket = socket.fromfd(self.nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)

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

        result = None

        if ip_hdr.p == ip.IP_PROTO_ICMP:
            container = self.container_mgr.get_container_by_ip(dst_ip)
            if container is not None:
                result = self.icmp_handler.handle(container, ip_hdr, ip_hdr.data)
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
