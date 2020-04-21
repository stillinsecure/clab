import logging
import socket
import netfilterqueue
from dpkt import icmp, ip
from utility import Net
from utility import get_key
from collections import namedtuple

HandlerResult = namedtuple('HandlerResult', 'modified, accept')


class TCPHandler:

    def __init__(self, container_mgr, proxy):
        self.proxy = proxy
        self.proxy_endpoint = self.proxy.endpoint
        self.container_mgr = container_mgr

    def close(self):
        pass
    
    def process(self, ip_hdr, tcp_hdr):
        src_ip = Net.ipbytes_to_int(ip_hdr.src)
        dst_ip = Net.ipbytes_to_int(ip_hdr.dst)

        logging.debug('TCPHandler.process_packet(tcp): %s:%s -> %s:%s',
                      Net.ipint_to_str(src_ip), tcp_hdr.sport,
                      Net.ipint_to_str(dst_ip), tcp_hdr.dport)

        # Output data coming from the proxy
        if src_ip == self.proxy_endpoint.ip_int and tcp_hdr.sport == self.proxy_endpoint.port:
            key = get_key(tcp_hdr.dport, dst_ip)
            # Grab the addr of the docker container to modify
            # the outgoing packets to the original source
            src, sport = self.proxy.source_addrs.get(key, (None, None))
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
                key = get_key(tcp_hdr.sport, src_ip)
                logging.debug(
                    'TCPHandler.process_packet(tcp): Using the key %s ', key)
                self.proxy.source_addrs[key] = (ip_hdr.dst, tcp_hdr.dport)
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
