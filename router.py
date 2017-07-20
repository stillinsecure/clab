import netfilterqueue
import asyncio
import socket
from container import ContainerManager
from dpkt import ip, tcp, icmp
from utility import IPAddress
from configuration import Configuration
from log import write
from handlers.icmp import ICMPHandler

class Proxy:

    def __init__(self, queue_num, container_mgr, proxy_ip, proxy_port):
        self.proxy_ip = IPAddress.str_to_int(proxy_ip)
        self.proxy_ip_b = IPAddress.str_to_bytes(proxy_ip)
        self.proxy_port = proxy_port

class NFQueueManager:

    def __init__(self, queue_num, container_mgr, proxy_ip, proxy_port):
        self.proxy_ip = IPAddress.str_to_int(proxy_ip)
        self.proxy_ip_b = IPAddress.str_to_bytes(proxy_ip)
        self.proxy_port = proxy_port
        self.nfqueue = netfilterqueue.NetfilterQueue()
        self.queue_num = queue_num
        self.source_addrs = {}
        self.container_mgr = container_mgr
        self.nfq_socket = None
        self.icmp_handler = ICMPHandler()

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
        finally:
            writer.close()

    async def client_connected(self, client_reader, client_writer):

        start_data = None

        # Read a bit of data to see if this is just a scanner doing
        # a SYN scan. There is no need to start a container for this.
        try:
            client_addr = client_writer.get_extra_info('peername')
            ip = IPAddress.str_to_int(client_addr[0])
            key = self.get_key(client_addr[1], str(ip))
            container_addr = self.source_addrs[key]
            start_data = await client_reader.read(2048)
        except ConnectionResetError:
            client_writer.close()
            return

        host = IPAddress.bytes_to_int(container_addr[0])
        port = container_addr[1]

        # Start the container for the specified address
        name = await self.container_mgr.start_if_not_running(host, port)

        if name is None:
            print('Unable to start {}'.format(name))
            client_writer.close()
            return

        host = IPAddress.int_to_str(host)

        # It might take a couple of tries to hit the container until it
        # fully spins up
        for retry in range(0,5):
            try:

                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port ),
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
                continue

        client_writer.close()

    def start(self):
        self.nfqueue.bind(self.queue_num, self.process_packet)

        self.nfq_socket = socket.fromfd(self.nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)

        task = asyncio.ensure_future(self.container_mgr.monitor_idle_containers())

        listen_ip = IPAddress.int_to_str(self.proxy_ip)

        #asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        loop = asyncio.get_event_loop()
        # Register the file descriptor for read event
        loop.add_reader(self.nfq_socket.fileno(), self.reader)

        server = loop.run_until_complete(
            asyncio.start_server(self.client_connected,
                                 host=listen_ip,
                                 port=self.proxy_port)
        )

        loop.run_forever()

    def stop(self):
        self.nfqueue.unbind()

    def reader(self):
        data = self.nfq_socket.recv(2048)
        self.nfqueue.get_packet(data)

    def get_key(self, port, ip):
        return ''.join([str(port), str(ip)])

    def process_packet(self, pkt):
        ip_hdr = ip.IP(pkt.get_payload())
        tcp_hdr = ip_hdr.data
        modified = False

        if ip_hdr.p == ip.IP_PROTO_ICMP:
            dst_ip = IPAddress.bytes_to_int(ip_hdr.dst)
            container_name = self.container_mgr.get_container_name(dst_ip)
            if container_name is not None:
                self.icmp_handler.handle(container_name, ip_hdr, ip_hdr.data)

        if ip_hdr.p == ip.IP_PROTO_TCP:
            src_ip = IPAddress.bytes_to_int(ip_hdr.src)
            dst_ip = IPAddress.bytes_to_int(ip_hdr.dst)

            # Output data coming from the proxy
            if src_ip == self.proxy_ip and tcp_hdr.sport == self.proxy_port:
                key = self.get_key(tcp_hdr.dport, dst_ip)
                # Grab the addr of the docker container to modify
                # the outgoing packets to the original source
                src, sport = self.source_addrs[key]
                ip_hdr.src = src
                tcp_hdr.sport = sport
                modified = True
            # Input data coming to the NFQUEUE
            else:
                # See if there is a container registered to the specified dst and port
                container_name = self.container_mgr.get_container_name(dst_ip, tcp_hdr.dport)

                # Only redirect to the proxy if this packet is for a container
                if container_name is not None:
                    # Store the dst address of the docker container so that
                    # outgoing packets can be modified with the correct
                    # source addr above
                    key = self.get_key(tcp_hdr.sport, src_ip)
                    self.source_addrs[key] = (ip_hdr.dst, tcp_hdr.dport)
                    # Modify the ip header so that the packet goes to the proxy server
                    ip_hdr.dst = self.proxy_ip_b
                    tcp_hdr.dport = self.proxy_port
                    modified = True
                else:
                    # This packet is not associated with a container so drop it
                    # This should never happen unless the iptable rules are bad
                    pkt.drop()
                    return

            if modified:
                # Since the headers have been modified the chksums are
                # cleared and are recalculated in bytes conversion by dpkt
                ip_hdr.sum = 0
                tcp_hdr.sum = 0
                pkt.set_payload(bytes(ip_hdr))

            pkt.accept()

if __name__ == '__main__':
    config = Configuration('unit_test_cfg.yaml')
    cm = ContainerManager(config)
    cm.start()
    n = NFQueueManager(0, cm, '192.168.1.9', 5996)
    n.start()


