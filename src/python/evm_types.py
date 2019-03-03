import logging
import os
import codecs
import random
import json

# EVM Types
type_list = {
    "uint256": {
        "type": "number",
        "size": 256
    },

    "payment": {
        "type": "number",
        "size": 256
    },

    "address": {
        "type": "address",
        "size": 160
    }
}

mode_list = [
    "min",
    "max",
    "random",
    "seed"
]

seed_dir = os.path.join(os.path.dirname(__file__), "../static/seed")

class TypeHandler():
    def __init__(self, _seed_dir=seed_dir, _type_list=type_list, _mode_list=mode_list):
        self.seeds = {}
        self.type_list = _type_list
        self.mode_list = _mode_list
        for _type in list(self.type_list.keys()):
            json_file = os.path.join(_seed_dir, _type+".json")
            with open(json_file, "r") as f:
                self.seeds[_type] = list(json.load(f))

    @staticmethod
    def generateMinValue(size):
        res = "0" * ((size - 1) // 4)
        tmp = (size - 1) % 4
        if tmp == 0:
            res = "1" + res
        elif tmp == 1:
            res = "2" + res
        elif tmp == 2:
            res = "4" + res
        else:
            res = "8" + res
        return res

    @staticmethod
    def generateMaxValue(size):
        res = "f" * ((size - 1) // 4)
        tmp = (size - 1) % 4
        if tmp == 0:
            res = "1" + res
        elif tmp == 1:
            res = "3" + res
        elif tmp == 2:
            res = "7" + res
        else:
            res = "f" + res
        return res

    def generateRandomValue(self, size):
        min_int = int(self.generateMinValue(size), 16)
        max_int = int(self.generateMaxValue(size), 16)
        rand_int = random.randint(min_int, max_int)
        # remove "L" for python2
        return hex(rand_int).rstrip("L").lstrip("0x") or "0"

    def generateValueByType(self, _type, mode="random"):
        type_obj = self.type_list[_type]
        if type_obj == None:
            logging.error("EVM type not found " + _type)
            return None
        if mode not in self.mode_list:
            logging.error("Incorrect mode for generateValueByType.")
            return None
        # seed mode
        if mode == "seed":
            type_seeds = self.seeds[_type]
            if type_seeds == None or len(type_seeds) == 0:
                logging.error("Cannot find seeds for ", _type)
                return None
            rand_index = random.randint(0, len(type_seeds)-1)
            return type_seeds[rand_index]
        # if not seed mode
        if type_obj["type"] == "number":
            num_size = random.randint(1, type_obj["size"])
            if mode == "min":
                return self.generateMinValue(num_size)
            elif mode == "max":
                return self.generateMaxValue(num_size)
            elif mode == "random":
                return self.generateRandomValue(num_size)
            else:
                logging.error("Incorrect mode for generateValueByType.")
                return None
        if type_obj["type"] == "address":
            # 'address' generation only support 'seed' mode
            logging.error("Only seed mode is acceptable for address generation.")
            return None
        else:
            logging.error("EVM type not found " + _type)
            return None
