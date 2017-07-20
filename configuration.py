import yaml

class Network():

    def __init__(self, cfg_dict):
        cfg = cfg_dict['network']
        self.address = cfg['address']
        self.name = cfg['name']

class Image():

    def __init__(self, cfg_dict):
        self.desc = cfg_dict['desc']
        self.name = cfg_dict['name']
        self.count = cfg_dict['count']

class Naming():

    def __init__(self, cfg_dict):
        cfg = cfg_dict['naming']
        self.word_file = cfg['word_file']
        self.min_host_len = cfg['min_host_len']
        self.max_host_len = cfg['max_host_len']
        self.allowable_host_chars = cfg['allowable_host_chars']


class Configuration():

    def __init__(self, file_name):
        self.images = []
        self.naming = None
        self.network = None
        self.__load(file_name)

    def __load(self, file_name):
        with  open(file_name, "r") as f:
            cfg = yaml.load(f)

            images_cfg = cfg['images']
            for image_cfg in images_cfg:
                image = Image(image_cfg)
                self.images.append(image)

            self.naming = Naming(cfg)
            self.network = Network(cfg)
