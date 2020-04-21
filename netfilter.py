import logging
import socket
import asyncio
import iptc
import netfilterqueue
from dpkt import icmp, ip
from protocolhandlers import (ICMPHandler, TCPHandler,
                              UDPHandler)
from proxies import TCPProxy
from utility import Net, TCPEndPoint

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
        prerouting_chain = iptc.Chain(iptc.Table(
            iptc.Table.MANGLE), IPTABLES_PREROUTING)

        for index in range(len(prerouting_chain.rules), 0, -1):
            rule = prerouting_chain.rules[index-1]
            if rule.target.name == self.config.router.chain_name:
                prerouting_chain.delete_rule(rule)

        output_chain = iptc.Chain(iptc.Table(
            iptc.Table.FILTER), IPTABLES_OUTPUT)

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
        logging.info('Setting up iptables')

        assert clab_network is not None and len(
            clab_network) > 1, 'A network address is required'
        assert ports is not None and len(
            ports) >= 1, 'Images need to be configured with TCP ports'

        proxy_port = self.config.router.proxy_port

        self.delete_clab_chain()

        # Create a new CLAB chain in the MANGLE and FILTER tables
        # to make it easier to manage the rules, ie drop the rules
        # on every run
        mangle_table = iptc.Table(iptc.Table.MANGLE)
        mangle_clab_chain = mangle_table.create_chain(
            self.config.router.chain_name)

        filter_table = iptc.Table(iptc.Table.FILTER)
        output_clab_chain = filter_table.create_chain(
            self.config.router.chain_name)

        tcp_ports = [str(port.num)
                     for port in ports if port.protocol == TCP_PROTOCOL]
        udp_ports = [str(port.num)
                     for port in ports if port.protocol == UDP_PROTOCOL]

        # Rule to send all tcp traffic for containers with matching ports to the NFQUEUE
        if tcp_ports is not None and len(tcp_ports) > 0:
            tcp_rule = iptc.Rule()
            tcp_rule.dst = clab_network
            tcp_rule.protocol = TCP_PROTOCOL_TXT
            tcp_match = tcp_rule.create_match(IPTABLES_MULTIPORT)
            tcp_match.dports = ','.join(tcp_ports)
            tcp_target = tcp_rule.create_target(IPTABLES_NFQUEUE)
            tcp_target.set_parameter(
                IPTABLES_QUEUE_NUM, self.config.router.queue_num)
            mangle_clab_chain.insert_rule(tcp_rule)

        # Rule to send all udp traffic for containers with matching ports to the NFQUEUE
        if udp_ports is not None and len(udp_ports) > 0:
            udp_rule = iptc.Rule()
            udp_rule.dst = clab_network
            udp_rule.protocol = UDP_PROTOCOL_TXT
            udp_match = udp_rule.create_match(IPTABLES_MULTIPORT)
            udp_match.dports = ','.join(udp_ports)
            udp_target = udp_rule.create_target(IPTABLES_NFQUEUE)
            udp_target.set_parameter(
                IPTABLES_QUEUE_NUM, self.config.router.queue_num)
            mangle_clab_chain.insert_rule(udp_rule)

        # Rule to send all icmp traffic for containers to the NFQUEUE
        icmp_rule = iptc.Rule()
        icmp_rule.dst = clab_network
        icmp_rule.protocol = ICMP_PROTOCOL_TXT
        icmp_target = icmp_rule.create_target(IPTABLES_NFQUEUE)
        icmp_target.set_parameter(
            IPTABLES_QUEUE_NUM, self.config.router.queue_num)
        mangle_clab_chain.insert_rule(icmp_rule)

        # Rule to send all output packets from the proxy back to the NFQUEUE
        # Proxy rule for tcp
        proxy_rule = iptc.Rule()
        proxy_rule.protocol = TCP_PROTOCOL_TXT
        proxy_match = proxy_rule.create_match(TCP_PROTOCOL_TXT)
        proxy_match.sport = str(proxy_port)
        proxy_target = proxy_rule.create_target(IPTABLES_NFQUEUE)
        proxy_target.set_parameter(
            IPTABLES_QUEUE_NUM, self.config.router.queue_num)
        output_clab_chain.insert_rule(proxy_rule)

        # Create RULES to send traffic to the CLAB chain
        prerouting_chain = iptc.Chain(iptc.Table(
            iptc.Table.MANGLE), IPTABLES_PREROUTING)
        prerouting_rule = iptc.Rule()
        prerouting_rule.create_target(self.config.router.chain_name)
        prerouting_chain.insert_rule(prerouting_rule)

        output_chain = iptc.Chain(iptc.Table(
            iptc.Table.FILTER), IPTABLES_OUTPUT)
        output_rule = iptc.Rule()
        output_rule.create_target(self.config.router.chain_name)
        output_chain.insert_rule(output_rule)


class NetfilterQueueHandler:

    def __init__(self, container_mgr, config):
        self.proxy_endpoint = TCPEndPoint(
            config.router.get_interface_ip(), config.router.proxy_port)
        self.nfqueue = netfilterqueue.NetfilterQueue()
        self.queue_num = config.router.queue_num
        self.container_mgr = container_mgr
        self.nfq_socket = None
        self.icmp_handler = ICMPHandler(config)
        self.proxy = TCPProxy(container_mgr, self.proxy_endpoint)
        self.tcp_handler = TCPHandler(container_mgr, self.proxy)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def start(self, loop):
        logging.info('Binding nfqueue')
        self.nfqueue.bind(int(self.queue_num), self.process_packet)
        self.nfq_socket = socket.fromfd(
            self.nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)

        self.proxy.start(loop)
        # Register the file descriptor for read event
        loop.add_reader(self.nfq_socket, self.reader)
        loop.run_forever()

    def stop(self):
        self.nfqueue.unbind()
        # If the queue bind failed the socket will be None
        if not self.nfq_socket is None: 
            self.nfq_socket.close()
        self.icmp_handler.close()
        self.tcp_handler.close()

    def reader(self):
        self.nfqueue.get_packet(self.nfq_socket)

    def process_packet(self, pkt):
        ip_hdr = ip.IP(pkt.get_payload())
        dst_ip = Net.ipbytes_to_int(ip_hdr.dst)
        src_ip = Net.ipbytes_to_int(ip_hdr.src)

        '''
        logging.debug('Process_packet(tcp): %s:%s',
                      Net.ipint_to_str(src_ip), Net.ipint_to_str(dst_ip))
        '''
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

        if ip_hdr.p == ip.IP_PROTO_ICMP:
            container = self.container_mgr.get_container_by_ip(dst_ip)
            if container is not None:
                result = self.icmp_handler.handle(
                    container, ip_hdr, ip_hdr.data)
                # ICMP requests are replied to by the handler so they will be dropped'
                pkt.drop()

