import re
import random
from models import Container

class Naming:

    def __init__(self):
        pass

    def generate_host_names(self, naming_cfg, count):
        
        containers = Container.select(Container.name)

        unique_hosts = {}
       
        with open(naming_cfg.word_file, "r") as f:
            array = []
            for line in f:
                word = re.sub(naming_cfg.allowable_host_chars, "", line.lower())
                word_len = len(word)
                if word_len >= naming_cfg.min_host_len and \
                                word_len <= naming_cfg.max_host_len:
                    array.append(word)
        
            while len(unique_hosts) < count:
                index = random.randint(1, len(array))
                name = array[index-1]
                if not name in unique_hosts and name not in containers:
                    unique_hosts[name] = name

            return list(unique_hosts)

