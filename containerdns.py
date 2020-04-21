import ipaddress
import logging
import pdb

import dnslib.server
from dnslib import QTYPE, RCODE, RR, PTR
from dnslib.server import BaseResolver, DNSHandler, DNSLogger, DNSServer

from utility import Net


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
            container = self.container_mgr.get_container_by_name(ques_name)  
            if not container is None:
                rr = RR(rname=container.ip)
                reply.add_answer(rr)
        elif ques_type == 'PTR':
            ip = Net.ptrqn_to_ipint(ques_name)
            container = self.container_mgr.get_container_by_ip(ip)
            if not container is None:
                fqdn = ''.join([container.name, '.', self.domain])
                rr = RR(rname=request.q.qname, rdata=PTR(fqdn), rtype=QTYPE.PTR, ttl=3600)
                reply.add_answer(rr)
   
        return reply

class ContainerDnsServer(object):

    def __init__(self, container_mgr, domain):
        resolver = ContainerResolver(container_mgr, domain)
        self.server = dnslib.server.DNSServer(resolver=resolver, logger=DNSLogger("pass"))
        self.server.start_thread()
