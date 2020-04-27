import asyncio
import logging
import socket

import iptc
import netfilterqueue
from dpkt import icmp, ip, tcp

from proxies import ContainerProxy
from utility import Net, TCPEndPoint, get_key

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
            iptc.Table.NAT), IPTABLES_PREROUTING)

        for index in range(len(output_chain.rules), 0, -1):
            rule = output_chain.rules[index-1]
            if rule.target.name == self.config.router.chain_name:
                output_chain.delete_rule(rule)

        self.delete_chain(iptc.Table.MANGLE, self.config.router.chain_name)
        self.delete_chain(iptc.Table.NAT, self.config.router.chain_name)

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

        self.delete_clab_chain()

        # Create a new CLAB chain in the MANGLE and FILTER tables
        # to make it easier to manage the rules, ie drop the rules
        # on every run
        mangle_table = iptc.Table(iptc.Table.MANGLE)
        mangle_clab_chain = mangle_table.create_chain(
            self.config.router.chain_name)

        nat_clab_chain = iptc.Table(iptc.Table.NAT)
        nat_clab_chain = nat_clab_chain.create_chain(
            self.config.router.chain_name)

        tcp_ports = [str(port.num)
                     for port in ports if port.protocol == TCP_PROTOCOL]
        udp_ports = [str(port.num)
                     for port in ports if port.protocol == UDP_PROTOCOL]

        if tcp_ports is not None and len(tcp_ports) > 0:
            # Rule to send SYN packets to the NFQUEUE to track the container
            # destination as well as act as a firewall to drop packets destined
            # for services or containers that do not exist
            tcp_rule = iptc.Rule()
            tcp_rule.dst = clab_network
            tcp_rule.protocol = TCP_PROTOCOL_TXT
            state_match = tcp_rule.create_match('tcp')
            state_match.tcp_flags = 'SYN'
            multiport_match = tcp_rule.create_match('multiport')
            multiport_match.dports = ','.join(tcp_ports)
            queue_target = tcp_rule.create_target(IPTABLES_NFQUEUE)
            queue_target.set_parameter(
                IPTABLES_QUEUE_NUM, self.config.router.queue_num)

            mangle_clab_chain.insert_rule(tcp_rule)

            # Rule to send all traffic to the proxy
            tcp_rule = iptc.Rule()
            tcp_rule.dst = clab_network
            tcp_rule.protocol = TCP_PROTOCOL_TXT
            multiport_match = tcp_rule.create_match('multiport')
            multiport_match.dports = ','.join(tcp_ports)
            connmark_target = tcp_rule.create_target('REDIRECT')
            connmark_target.set_parameter('to-ports', '5996')
            nat_clab_chain.insert_rule(tcp_rule)

        # Rule to send all icmp traffic for containers to the NFQUEUE
        icmp_rule = iptc.Rule()
        icmp_rule.dst = clab_network
        icmp_rule.protocol = ICMP_PROTOCOL_TXT
        icmp_target = icmp_rule.create_target(IPTABLES_NFQUEUE)
        icmp_target.set_parameter(
            IPTABLES_QUEUE_NUM, self.config.router.queue_num)
        mangle_clab_chain.insert_rule(icmp_rule)
        
        # Create a rule to send traffic to the CLAB chain from
        # the mangle table prerouting chain
        mangle_prerouting_chain = iptc.Chain(iptc.Table(
            iptc.Table.MANGLE), IPTABLES_PREROUTING)
        prerouting_rule = iptc.Rule()
        prerouting_rule.create_target(self.config.router.chain_name)
        mangle_prerouting_chain.insert_rule(prerouting_rule)

        # Create a rule to send traffic to the CLAN chain from
        # the nat table prerouting chain
        nat_prerouting_chain = iptc.Chain(iptc.Table(
            iptc.Table.NAT), IPTABLES_PREROUTING)
        prerouting_rule = iptc.Rule()
        prerouting_rule.create_target(self.config.router.chain_name)
        nat_prerouting_chain.insert_rule(prerouting_rule)


class ContainerFirewall:

    def __init__(self, container_mgr, queue_num):
        self.nfqueue = netfilterqueue.NetfilterQueue()
        self.queue_num = queue_num
        self.nfq_socket = None
        self.container_addrs = {}
        self.container_mgr = container_mgr
        self.icmp_client = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, ip.IP_PROTO_RAW)
        self.icmp_client.setblocking(False)
        self.icmp_client.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, True)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def start(self, loop):
        logging.info('Starting container firewall on NFQUEUE %s',
                     self.queue_num)

        self.nfqueue.bind(int(self.queue_num), self.process_packet)
        self.nfq_socket = socket.fromfd(
            self.nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)

        # Register the file descriptor for read event
        loop.add_reader(self.nfq_socket, self.reader)

    def stop(self):
        self.nfqueue.unbind()
        # If the queue bind failed the socket will be None
        if not self.nfq_socket is None:
            self.nfq_socket.close()

    def reader(self):
        self.nfqueue.get_packet(self.nfq_socket)

    def process_packet(self, pkt):
        ip_hdr = ip.IP(pkt.get_payload())
        dst_ip = Net.ipbytes_to_int(ip_hdr.dst)
        src_ip = Net.ipbytes_to_int(ip_hdr.src)

        if ip_hdr.p == ip.IP_PROTO_TCP:
            tcp_hdr = ip_hdr.data
            # See if there is a container registered to the specified dst and port
            container = self.container_mgr.get_container_by_endpoint(
                dst_ip, tcp_hdr.dport, 6)

            # Only track if this is for a container
            if container is not None:
                logging.debug(
                    'TCPHandler.process_packet(tcp): Found container %s', container.name)

                # Store the dst address of the docker container so that
                # outgoing packets can be modified with the correct
                # source addr above
                key = get_key(tcp_hdr.sport, src_ip)
                self.container_addrs[key] = (dst_ip, tcp_hdr.dport)
                pkt.set_mark(dst_ip)
                pkt.accept()
            else:
                pkt.drop()
        elif  ip_hdr.p == ip.IP_PROTO_ICMP:
            # Drop all ICMP packets since the client will respond with
            # the matching container
            pkt.drop()
            
            container = self.container_mgr.get_container_by_ip(dst_ip)

            if container is not None:
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
    
        
