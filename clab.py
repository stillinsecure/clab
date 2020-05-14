#!/usr/bin/env python3
import os
import aiodocker
import asyncio
import argparse
import logging
import sys
import traceback
from dns import ContainerDnsServer
from proxies import ContainerProxy
from configuration import Configuration
from container import ContainerManager, ContainerBuilder
from models import close_database, setup_database
from netfilter import ContainerFirewall, TCPEndPoint, IPTableRules
from multiprocessing import Process, Pool

BANNER = """
       _           _      
      | |         | |     
   ___| |     __ _| |__   
  / __| |    / _` | '_ \  
 | (__| |___| (_| | |_) | 
  \___|______\__,_|_.__/                                                          
"""

CONTACT_INFO = """
Darren Southern 
@stillinsecure
https://github.com/stillinsecure/clab
"""

def setup_logging(instance):   
    pid = os.getpid()
    logging._srcfile = None
    logging.logThreads = 1
    logging.logProcesses = 0

    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    logging.basicConfig(filename='logs/{}-clab.out'.format(pid),
        format='[{}:{}] %(asctime)s %(levelname)-8s %(message)s'.format(instance, pid),
        level=logging.INFO,
        datefmt='%Y-%m-%d %H:%M:%S')

def start_firewall(instance):
    instance = instance - 1

    try:
        setup_logging(instance)
        loop = asyncio.get_event_loop()

        config.firewall.proxy_port = config.firewall.proxy_port + instance
        config.firewall.queue_num = instance 

        container_mgr = ContainerManager(config)
        loop.run_until_complete(container_mgr.start())

        firewall = ContainerFirewall(container_mgr, config.firewall.queue_num)
        firewall.start(loop)
        
        proxy_server = ContainerProxy(container_mgr, config)
        loop.run_until_complete(proxy_server.start(loop))
        loop.run_forever()
    finally:
        loop.run_until_complete(container_mgr.stop())

def start_dns_server(config):
    setup_logging(0)
        
    container_mgr = ContainerManager(config)
  
    with ContainerDnsServer(container_mgr, config.network.domain) as dns_server:
        dns_server.start()
    
if __name__ == '__main__':
    
    parser = argparse.ArgumentParser('Run clab')
    parser.add_argument('--run', action='store_true',
                        help='Runs the current deployment')
    parser.add_argument('--create', action='store_true',
                        help='Create and run a new deployment')
    parser.add_argument('--delete', action='store_true',
                        help='Delete the current deployment')
    parser.add_argument('--view', action='store_true',
                        help='View current deployment')
    parser.add_argument('--config', default='config.yaml',
                        help='yaml file used to configure a deployment')
    parser.add_argument('--ignore', default='store_true',
                        help='Ignore configuration changes detection')                    
    parser.add_argument('--update', action='store_true',
                        help='Images defined in the config file are appended to the current deployment')     
    args = parser.parse_args()

    print(BANNER)
    print(CONTACT_INFO) 
    
    # Sets up the database for Peewee ORM
    setup_database()
    config = Configuration()
    config.open(args.config)
    
    # Displays the current deployment
    if args.view:
        builder = ContainerBuilder(config)
        builder.view()
    # Deletes the docker containers and entries in the containers.db
    elif args.delete:    
        loop = asyncio.get_event_loop()
        builder = ContainerBuilder(config)
        loop.run_until_complete(builder.delete_containers())

    elif args.create or args.run or args.update:
        
        # Create a new deployment, this overwrites any existing deployment
        if args.create or args.update:
            setup_logging(0)
            loop = asyncio.get_event_loop()
            builder = ContainerBuilder(config)
            loop.run_until_complete(builder.create_containers(args.update))

        # Start the firewall/proxy using a worker pool 
        if args.run:
            dns_server_process = Process(target=start_dns_server, args=(config, ))
            dns_server_process.daemon = True
            dns_server_process.start()

            pool = Pool(config.firewall.instances)
            pool.map(start_firewall, range(1, config.firewall.instances + 1))
  
