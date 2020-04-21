#!/usr/bin/env python3
import aiodocker
import asyncio
import argparse
import logging
import sys
import traceback
import containerdns
from configuration import Configuration
from container import ContainerManager
from models import close_database, setup_database
from netfilter import NetfilterQueueHandler

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

if __name__ == '__main__':

    loop = asyncio.get_event_loop()
    
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
        logging.basicConfig(level=logging.INFO)

        # Sets up the database for Peewee ORM
        setup_database()

        config = Configuration()
        config.open(args.config)

        ctr_mgr = ContainerManager(config)
        
        # Displays the current deployment
        if args.view:
            ctr_mgr.view()
        # Deletes the docker containers and entries in the containers.db
        elif args.delete:
            loop.run_until_complete(ctr_mgr.delete_containers())
            loop.run_until_complete(ctr_mgr.stop())
        elif args.create or args.run:
            # Create a new deployment, this overwrites any existing deployment
            if args.create:
                loop.run_until_complete(ctr_mgr.create_containers())
                loop.run_until_complete(ctr_mgr.stop())
            if args.run:
                # Start the container manager that monitors containers for
                # activity
                ctr_mgr.start()
                #containerdns.ContainerDnsServer(ctr_mgr, config.network.domain)
                # Start up the networkhandler that takes care of the NFQUEUE
                # and TCP proxy
                with NetfilterQueueHandler(ctr_mgr, config) as net_handler:
                    net_handler.start(loop)
    except Exception as e:
        traceback.print_exc(file=sys.stdout)
        print(e)
    finally:
        close_database()
        loop.close()