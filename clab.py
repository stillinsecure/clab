from network import NetworkHandler
from configuration import Configuration
from container import ContainerManager
from models import setup_database, close_database
import argparse
import logging
import traceback
import sys

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

    try:
        parser = argparse.ArgumentParser('Run clab')
        parser.add_argument('--run', action='store_true', help='Runs the current deployment')
        parser.add_argument('--create', action='store_true', help='Create and run a new deployment')
        parser.add_argument('--delete', action='store_true', help='Delete the current deployment')
        parser.add_argument('--view', action='store_true', help='View current deployment')
        parser.add_argument('--config', default='config.yaml', help='yaml file used to configure a deployment')
        parser.add_argument('--ignore', default='store_true', help='Ignore configuration changes detection')

        args = parser.parse_args()

        print(BANNER)
        print(CONTACT_INFO)

        # Configure logging
        logging.basicConfig(level=logging.DEBUG)

        # Sets up the database for Peewee ORM
        setup_database()

        config = Configuration()
        config.open(args.config)

        with ContainerManager(config) as ctr_mgr:
            # Displays the current deployment
            if args.view:
                ctr_mgr.view()
            # Deletes the docker containers and entries in the containers.db
            elif args.delete:
                ctr_mgr.delete_containers()
            elif args.create or args.run:
                # Create a new deployment, this overwrites any existing deployment
                if args.create:
                    ctr_mgr.create_containers()
                    ctr_mgr.view()
                if args.run:
                    # Start the container manager that monitors containers for
                    # activity
                    ctr_mgr.start()
                    # Start up the networkhandler that takes care of the NFQUEUE
                    # and TCP proxy
                    with NetworkHandler(ctr_mgr, config) as net_handler:
                        net_handler.start()
    except Exception as e:
        traceback.print_exc(file=sys.stdout)
        print(e)
    finally:
        close_database()
