import yaml

class Network(yaml.YAMLObject):
    yaml_tag = u'Network'

    def __init__(self, name, network, gateway):
        self.network = network
        self.gateway = gateway

class HostDefinition(yaml.YAMLObject):
    yaml_tag = u"HostDefinition"

    def __init__(self, desc, image, count, ports):
        self.desc = desc
        self.image = image
        self.count = count
        self.ports = ports


class NamingConfig(yaml.YAMLObject):
    yaml_tag = u"Naming"

    def __init__(self, word_file="en.txt",
                 min_host_len=5,
                 max_host_len=10,
                 allowable_host_chars="[^a-z0-9]"):
        self.word_file = word_file
        self.min_host_len = min_host_len
        self.max_host_len = max_host_len
        self.allowable_host_chars = allowable_host_chars


class Configuration(yaml.YAMLObject):
    yaml_tag = u'Configuration'

    def __init__(self, host_defs,
                 naming=NamingConfig()):
        self.host_defs = host_defs
        self.naming = naming

    @staticmethod
    def load(file_name):
        f = open(file_name, "r")
        return yaml.load(f)

    @staticmethod
    def save(config, file_name):
        f = open(file_name, "w")
        yaml.dump(config, f, default_flow_style=False)
