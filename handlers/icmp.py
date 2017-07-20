import socket
from utility import IPAddress
from dpkt import icmp
from dpkt import ip
from log import write

class ICMPHandler():

    def __init__(self):
        self.icmp_client = socket.socket(socket.AF_INET, socket.SOCK_RAW, ip.IP_PROTO_RAW)
        self.icmp_client.setblocking(False)
        self.icmp_client.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, True)

    def handle(self, container_name, ip_hdr, icmp_hdr):

        if icmp_hdr.type == icmp.ICMP_ECHO:
            write('Echo request for {0}'.format(container_name), 'green')
            icmp_reply = ip.IP(bytes(ip_hdr))
            icmp_reply.src = ip_hdr.dst
            icmp_reply.dst = ip_hdr.src
            icmp_reply.data.type = icmp.ICMP_ECHOREPLY
            icmp_reply.sum = 0
            self.icmp_client.sendto(bytes(icmp_reply), (IPAddress.bytes_to_str(ip_hdr.src), 0))
