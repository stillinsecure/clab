#!/usr/bin/env python3
import aiodocker
import asyncio
import argparse
import logging
import sys
import traceback
from dns import ContainerDnsServer
from proxies import ContainerProxy
from configuration import Configuration
from container import ContainerManager
from models import close_database, setup_database
from netfilter import ContainerFirewall, TCPEndPoint
from multiprocessing import Process

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
https://github.com/stillinsecure/crouter
"""

def view_containers(config):
    container_mgr = ContainerManager(config)
    container_mgr.start()
    container_mgr.view()
    
def delete_containers(config):
    loop = asyncio.get_event_loop()
    container_mgr = ContainerManager(config)
    container_mgr.start()
    loop.run_until_complete(container_mgr.delete_containers())
    loop.run_until_complete(container_mgr.stop())
    loop.close()

def create_containers(config):
    loop = asyncio.get_event_loop()
    container_mgr = ContainerManager(config)
    container_mgr.start()
    loop.run_until_complete(container_mgr.create_containers())
    loop.run_until_complete(container_mgr.stop())
    loop.close()

def start_proxy_server(config, firewall, loop, container_mgr):
    proxy_server_co = None

    try:
        proxy_endpoint = TCPEndPoint(config.router.get_interface_ip(), config.router.proxy_port)
        proxy_server = ContainerProxy(container_mgr, proxy_endpoint, firewall)
        proxy_server_cr = proxy_server.start(loop)
        loop.run_until_complete(proxy_server_cr)
        loop.run_forever()
    except Exception as ex:
        logging.error(ex)
    finally:
        proxy_server_cr.close()
        loop.run_until_complete(proxy_server_co.wait_closed())
        
def start_dns_server(config, container_mgr):
    with ContainerDnsServer(container_mgr, config.network.domain) as dns_server:
        dns_server.start()
    
    container_mgr.stop()

if __name__ == '__main__':
    
    loop = asyncio.get_event_loop()
    dns_server_process = None
    container_mgr = None

    try:
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
        args = parser.parse_args()


        print(BANNER)
        print(CONTACT_INFO)

        # Configure logging
        #logging.disable()
        logging._srcfile = None
        logging.logThreads = 1
        logging.logProcesses = 0
        logging.basicConfig(
            format='%(asctime)s %(levelname)-8s %(message)s',
            level=logging.INFO,
            datefmt='%Y-%m-%d %H:%M:%S')
        # Sets up the database for Peewee ORM
        setup_database()
        config = Configuration()
        config.open(args.config)

        container_mgr = ContainerManager(config)
        container_mgr.start()

        # Displays the current deployment
        if args.view:
            view_containers(config)
        # Deletes the docker containers and entries in the containers.db
        elif args.delete:
            delete_containers(config)
        elif args.create or args.run:
            
            # Create a new deployment, this overwrites any existing deployment
            if args.create:
                create_containers(config)          
            
            # Start the tcp proxy
            if args.run:
                dns_server_process = Process(target=start_dns_server, args=(config, container_mgr))
                dns_server_process.start()

                firewall = ContainerFirewall(container_mgr, 0)
                firewall.start(loop)

                start_proxy_server(config, firewall, loop, container_mgr)

    except Exception as e:
        traceback.print_exc(file=sys.stdout)
        print(e)
    finally:
        close_database()
        loop.run_until_complete(container_mgr.stop())
        loop.close()

        if not dns_server_process is None:
            dns_server_process.terminate()
            dns_server_process.join()
            dns_server_process.close()

        
