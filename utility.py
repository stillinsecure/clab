import struct
import socket

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