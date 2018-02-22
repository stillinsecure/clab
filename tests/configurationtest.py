from configuration import Configuration, ConfigurationException
import unittest


class ConfigUnitTest(unittest.TestCase):

    def test_create_instance(self):
        conf = Configuration()
        self.assertIsNotNone(conf)

    def test_handle_non_existent_conf(self):
        conf = Configuration()
        with self.assertRaises(ConfigurationException):
            conf.open('doesnotexist.yaml')

    def test_handle_invalid_yaml(self):
        conf = Configuration()
        with self.assertRaises(ConfigurationException):
            conf.open('data/invalidyaml')

    def test_handle_invalid_conf(self):
        conf = Configuration()
        with self.assertRaises(ConfigurationException):
            conf.open('data/invalidconfig.yaml')


if __name__ == '__main__':
    unittest.main()