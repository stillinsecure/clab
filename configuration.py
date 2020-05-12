import hashlib
import yaml
import netifaces
import re
from os import path
import logging

HASH_FILE = 'config.sha256'


class BaseConfig:

    def __init__(self, cfg_dict, section):
        """
        Retrieves the config section from the cfg_dict. The section is
        a config dictionary itself
        """
        if section is None:
            self.cfg_dict = cfg_dict
        else:
            self.cfg_dict = self.get_config_dictionary(cfg_dict, section)

        if type(cfg_dict) is not dict:
            raise ConfigurationException(
                'Config section {} is not a dictionary'.format(section))

    def get_config_dictionary(self, cfg_dict, name):
        """
        Returns a configuration dictionary within
        the dictionary passed in to the constructor
        """
        if name is None:
            raise ConfigurationException(
                'Config dictionary section name is None')

        if name not in cfg_dict:
            raise ConfigurationException(
                'Could not find the config dictionary {}'.format(name))

        return cfg_dict[name]

    def get_config_setting(self, setting, default=None, regex=None):
        """
        Returns the specified setting within the config dict
        """
        if setting is None:
            raise ConfigurationException('Setting name was empty')

        if default is None and setting not in self.cfg_dict:
            raise ConfigurationException(
                'Could not find the setting {}'.format(setting))

        if setting not in self.cfg_dict:
            return default

        value = self.cfg_dict[setting]

        if regex is not None and not re.match(regex, value):
            raise ConfigurationException(
                '{} is an invalud value for {}'.format(value, setting))

        return value


class FirewallConfig(BaseConfig):

    def __init__(self, cfg_dict):
        """
        interface - Name of the interface that the proxy server will bind to as well
        as the interface that will serve as the router to the container network.

        proxy_port - The port that the tcp proxy server will bind to
        """
        super().__init__(cfg_dict, 'firewall')
        self.queue_num = self.get_config_setting('queue_num')
        self.interface = self.get_config_setting('interface')
        self.proxy_port = self.get_config_setting('proxy_port')
        self.chain_name = self.get_config_setting('chain_name')
        self.max_containers = self.get_config_setting('max_containers', 40)
        self.read_buffer = self.get_config_setting('read_buffer', 1024)
        self.read_client = self.get_config_setting('read_client', False)
        self.instances = self.get_config_setting('instances')
        
    def get_interface_ip(self):
        """
        Returns the IP address assigned to the interface specified in the
        configuration
        """
        if self.interface is None:
            raise ConfigurationException(
                'An interface needs to be defined in the router config')

        try:
            interface = netifaces.ifaddresses(self.interface)
        except ValueError:
            raise ConfigurationException(
                'The interface {} is not valid'.format(self.interface))

        if netifaces.AF_INET in interface and len(interface[netifaces.AF_INET]) > 0:
            return interface[netifaces.AF_INET][0]['addr']

        raise ConfigurationException(
            'Could not find a valid ip address for the interface {}'.format(self.interface))


class NetworkConfig(BaseConfig):

    def __init__(self, cfg_dict):
        super().__init__(cfg_dict, 'container_network')
        self.address = self.get_config_setting('address')
        self.name = self.get_config_setting('name')
        self.domain = self.get_config_setting('domain')


class ImagesConfig(BaseConfig):

    def __init__(self, cfg_dict):
        """
        Iterator for the images config section
        """
        super().__init__(cfg_dict, 'images')
        self.index = 0
        self.images = []
        if not self.cfg_dict is None:
            for image_cfg in self.cfg_dict:
                self.images.append(ImageConfig(image_cfg))

    def __iter__(self):
        self.index = 0
        return self

    def __next__(self):
        if self.index >= len(self.images):
            raise StopIteration
        else:
            image = self.images[self.index]
            self.index += 1
            return image


class ImageConfig(BaseConfig):

    def __init__(self, cfg_dict):
        """
        desc - Description of the image
        name - Name of the image
        count - Number of containers to create
        start_delay - The amount of time to wait in between connection attempts to
                        the container.
        start_retry_count - The number of times to retry the connection to the container
        sub_domain - The sub domain to append to the host name
        """
        super().__init__(cfg_dict, None)
        self.desc = self.get_config_setting('desc')
        self.name = self.get_config_setting('name')
        self.count = self.get_config_setting('count')
        self.start_delay = self.get_config_setting('start_delay', 1)
        self.start_retry_count = self.get_config_setting('start_retry_count', 5)
        self.start_on_create = self.get_config_setting('start_on_create', False)
        self.sub_domain = self.get_config_setting('sub_domain', '')
        self.env_variables = self.get_config_setting('env_variables', [])
        self.startup_script = self.get_config_setting('startup_script', '')
        
class NamingConfig(BaseConfig):

    def __init__(self, cfg_dict):
        """
        Settings used to control the generation of host names
        for the containers.

        word_file - The word file to generate host names from
        min_host_len - The minimum host name length
        max_host_len - The maximum host name length
        allowable_host_chars - Regex of allowables characters for the host names
        """
        super().__init__(cfg_dict, 'naming')
        self.word_file = self.get_config_setting('word_file')
        self.min_host_len = self.get_config_setting('min_host_len')
        self.max_host_len = self.get_config_setting('max_host_len')
        self.allowable_host_chars = self.get_config_setting(
            'allowable_host_chars')

class ContainerManagerConfig(BaseConfig):

    def __init__(self, cfg_dict):
        """
        """
        super().__init__(cfg_dict, 'container_manager')
        self.client_pool = self.get_config_setting('client_pool', 25)
        self.max_containers = self.get_config_setting('max_containers', 50)
        self.poll_time = self.get_config_setting('poll_time', 1)
        self.expire_after = self.get_config_setting('expire_after')
        self.stop_per_iteration = self.get_config_setting('stop_per_iteration')
        
class ConfigurationException(Exception):
    pass


class Configuration():

    def __init__(self):
        self.images = None
        self.naming = None
        self.network = None
        self.firewall = None
        self.container_manager = None

    def open(self, file_name, ignore_changes=True):
        if not path.isfile(file_name):
            raise ConfigurationException(
                'Could not find the configuration file {}'.format(file_name))

        existing_hash = self.__read_hash()
        hash = self.__generate_hash(file_name)

        if existing_hash != hash and not ignore_changes:
            raise ConfigurationException('Config has changed')

        self.__write_hash(hash)

        with open(file_name, "r") as f:
            cfg = yaml.safe_load(f)
            if cfg == 'This is not a valid yaml config file':
                raise ConfigurationException(cfg)

            self.images = ImagesConfig(cfg)
            self.naming = NamingConfig(cfg)
            self.network = NetworkConfig(cfg)
            self.firewall = FirewallConfig(cfg)
            self.container_manager = ContainerManagerConfig(cfg)

    def __read_hash(self):
        if path.isfile(HASH_FILE):
            with open(HASH_FILE, 'r') as f:
                return f.read()
        return None

    def __write_hash(self, hash):
        with open(HASH_FILE, 'w') as f:
            f.write(hash)

    def __generate_hash(self, file_name):
        config_hash = hashlib.sha256()
        with open(file_name, 'rb') as f:
            for data in iter(lambda: f.read(4096), b''):
                config_hash.update(data)
        return config_hash.hexdigest()
