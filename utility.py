import struct
import socket
import netaddr

class IPAddress:

    @staticmethod
    def str_to_int(str_ip):
        return struct.unpack("!I", socket.inet_aton(str_ip))[0]

    @staticmethod
    def int_to_str(int_ip):
        return socket.inet_ntoa(struct.pack("!I", int_ip))

    @staticmethod
    def bytes_to_int(bytes_ip):
        return struct.unpack("!I", bytes_ip)[0]

    @staticmethod
    def str_to_bytes(str_ip):
        return socket.inet_aton(str_ip)

    @staticmethod
    def bytes_to_str(bytes_ip):
        return socket.inet_ntoa(bytes_ip)

    @staticmethod
    def generate_cidr(network, count):
        for prefix_len in range(32, 1, -1):
            cidr = '{0}/{1}'.format(network, prefix_len)
            temp_network = netaddr.IPNetwork(cidr)
            if temp_network.size >= count:
                return cidr

