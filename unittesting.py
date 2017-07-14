import asyncio
import unittest
from asyncdocker import AsyncDocker
from naming import Naming
from container import ContainerManager
from configuration import Configuration

cfg_file = "unit_test_cfg.yaml"

'''
class TestConfiguration(unittest.TestCase):
    def test_loadsave(self):
        host_defs = [HostDefinition(desc="NGINX", image="nginx:latest", count=10, network="docker-proxy", ports=[80, 443]), ]
        config = Configuration(host_defs=host_defs)
        Configuration.save(config, cfg_file)
        config = Configuration.load(cfg_file)

        self.assertIsNotNone(config, "Config from load is None")
        self.assertEqual(len(config.host_defs), 1, "Host definitions is not 1")
        self.assertEqual(config.naming.word_file, "en.txt")


class TestNaming(unittest.TestCase):
    def test_generate_host_names(self):
        config = Configuration.load(cfg_file)
        naming = Naming()
        host_names = naming.generate_host_names(config.naming, 100)
        self.assertEqual(len(host_names), 100, "Expecting 100 host names")

'''
class TestContainerManager(unittest.TestCase):
    def test_create_containers(self):
        config = Configuration.load(cfg_file)
        mgr = ContainerManager()

        #return
        mgr.create_containers(config.host_defs, config.naming)

    def test_build_container_map(self):
        mgr = ContainerManager()
        mgr.start()
'''
class TestAsyncDocker(unittest.TestCase):

    async def start_stop_container(self, name, docker):
        await docker.start_container(name)
        await docker.stop_container(name)

    def test_start_container(self):

        loop = asyncio.get_event_loop()

        try:
            docker = AsyncDocker()
            docker.open()
            result = loop.run_until_complete(self.start_stop_container('jested', docker))
        finally:
            docker.close()
'''


if __name__ == '__main__':
    unittest.main()