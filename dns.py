import ipaddress
import logging
import socket
import dnslib.server
import netfilterqueue
from dnslib import QTYPE, RCODE, RR, PTR, A
from dnslib.server import BaseResolver, DNSHandler, DNSLogger, DNSServer
from utility import Net
from dpkt import icmp, ip, tcp


class ContainerResolver(BaseResolver):

    def __init__(self, container_mgr, domain):
        self.container_mgr = container_mgr
        self.domain = domain

    def resolve(self, request, handler):
        ques_name = str(request.q.qname).lower()
        ques_type = str(QTYPE[request.q.qtype]).upper()

        reply = request.reply()

        logging.debug('Incoming DNS question %s %s', ques_name, ques_type)

        if ques_type == 'A':
            host_name = ques_name.split('.')
            host_name = host_name[0]
            container = self.container_mgr.get_container_by_name(host_name)
            if not container is None:
                rr = RR(rname=request.q.qname, rdata=A(
                    container.ip), rtype=QTYPE.A, ttl=3600)
                reply.add_answer(rr)
        elif ques_type == 'PTR':
            ip = Net.ptrqn_to_ipint(ques_name)
            container = self.container_mgr.get_container_by_ip(ip)
            if not container is None:
                if container.sub_domain is None:
                    fqdn = ''.join([container.name, '.', self.domain])
                else:
                    fqdn = ''.join(
                        [container.name, '.', container.sub_domain, '.', self.domain])
                rr = RR(rname=request.q.qname, rdata=PTR(
                    fqdn), rtype=QTYPE.PTR, ttl=3600)
                reply.add_answer(rr)

        return reply


class ContainerDnsServer(object):

    def __init__(self, ctr_mgr, domain_name):
        resolver = ContainerResolver(ctr_mgr, domain_name)
        self.server = dnslib.server.DNSServer(
            resolver=resolver, logger=DNSLogger("pass"))
        logging.info('Starting container DNS server')
       
    def __enter__(self):
        return self

    def start(self):
        self.server.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.server.stop()
