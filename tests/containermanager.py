import unittest
from container import ContainerManager
from configuration import Configuration

cfg_file = "unit_test_cfg.yaml"

class TestContainerManager(unittest.TestCase):

    def test_create_containers(self):
        config = Configuration(cfg_file)
        mgr = ContainerManager(config)
        mgr.create_containers()

    def test_setup_iptables(self):
        config = Configuration(cfg_file)
        mgr = ContainerManager(config)
        mgr.setup_iptables('10.0.0.0/24', '80, 22, 443')

if __name__ == '__main__':
    unittest.main()