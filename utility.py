import struct
import socket
import netaddr

class Net:

    @staticmethod
    def mac_to_bytes(str_mac):
        number = int(str_mac.replace(':', ''), 16)
        return bin(number)

    @staticmethod
    def ipstr_to_int(str_ip):
        return struct.unpack("!I", socket.inet_aton(str_ip))[0]

    @staticmethod
    def ipint_to_str(int_ip):
        return socket.inet_ntoa(struct.pack("!I", int_ip))

    @staticmethod
    def ipbytes_to_int(bytes_ip):
        return struct.unpack("!I", bytes_ip)[0]

    @staticmethod
    def ipstr_to_bytes(str_ip):
        return socket.inet_aton(str_ip)

    @staticmethod
    def ipbytes_to_str(bytes_ip):
        return socket.inet_ntoa(bytes_ip)

    @staticmethod
    def generate_cidr(network, count):
        for prefix_len in range(32, 1, -1):
            cidr = '{0}/{1}'.format(network, prefix_len)
            temp_network = netaddr.IPNetwork(cidr)
            if temp_network.size >= count:
                return cidr

    @staticmethod
    def cidr_to_iptables_dst(cidr):
        temp = netaddr.IPNetwork(cidr)
        return '{}/{}'.format(temp.network, temp.netmask)

    @staticmethod
    def generate_mac(ip):
        mac = '02:42'
        for octet in ip.split('.'):
            mac += ':{:02x}'.format(int(octet))
        return mac

class Dictionary:

    @staticmethod
    def get_attr(attrs, *args):

        if len(args) <= 0:
            raise Exception('No args specified for get_attr')

        for arg in args:
            if type(attrs) is not dict:
                raise TypeError('attrs is not a dictionary')
            if arg not in attrs:
                raise Exception('Could not find the attribute {}'.format(arg))
            attrs = attrs[arg]

        return attrs

    @staticmethod
    def has_attr(attrs, *args):
        if len(args) <= 0:
            raise Exception('No args specified for get_attr')

        for arg in args:
            if type(attrs) is not dict:
                raise TypeError('attrs is not a dictionary')
            if arg not in attrs:
                return False
            attrs = attrs[arg]

        return True