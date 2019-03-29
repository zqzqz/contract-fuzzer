import logging
import os
import codecs
import random
import json

from pyfuzz.config import DIR_CONFIG
from pyfuzz.utils.utils import hexCode, binaryToHex, hexToBinary

logger = logging.getLogger("types")

# EVM Types
type_list = {
    "uint": { "type": "uint", "size": 256 },
    "int": { "type": "int", "size": 256 },
    "address": { "type": "address", "size": 160 },
    "byte": { "type": "byte", "size": 8 },
    "bool": { "type": "bool", "size": 1 }
}

for i in range(8, 256 + 8, 8):
    type_list["uint" + str(i)] = {"type": "uint", "size": i}
    type_list["int" + str(i)] = {"type": "int", "size": i}

for key in list(type_list.keys()):
    type_list[key + "[]"] = {"type": "array",
                             "element_type": key, "size": None}

for i in range(1, 33):
    type_list["bytes" + str(i)] = {"type": "bytes", "size": i * 8}

type_list["payment"] = {"type": "uint", "size": 64}
type_list["string"] = {"type": "bytes", "size": None}


mode_list = [
    "min",
    "max",
    "random",
    "seed"
]

seed_dir = DIR_CONFIG["seed_dir"]


class TypeHandler():
    def __init__(self, _seed_dir=seed_dir, _type_list=type_list, _mode_list=mode_list):
        self.seeds = {}
        self.type_list = _type_list
        self.mode_list = _mode_list
        for _type in list(self.type_list.keys()):
            if type_list[_type]["type"] == "array":
                continue
            json_file = os.path.join(_seed_dir, _type+".json")
            if os.path.isfile(json_file):
                with open(json_file, "r") as f:
                    self.seeds[_type] = list(json.load(f))
            else:
                if type_list[_type]["type"] == "uint" or type_list[_type]["type"] == "int":
                    self.seeds[_type] = [
                        self.generateValueByType(_type, "min"),
                        self.generateValueByType(_type, "max")
                    ]
                else:
                    self.seeds[_type] = []

    def generateMinHexValue(self, size):
        if size == 0:
            return "0"
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

    def generateMinIntValue(self, size):
        hexStr = self.generateMinHexValue(size)
        return int(hexStr, 16)

    def generateMaxHexValue(self, size):
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

    def generateMaxIntValue(self, size):
        hexStr = self.generateMaxHexValue(size)
        return int(hexStr, 16)

    def generateRandomIntValue(self, size):
        min_int = self.generateMinIntValue(size)
        max_int = self.generateMaxIntValue(size)
        selected_int = random.randint(min_int, max_int)
        return selected_int

    def generateRandomHexValue(self, size):
        selected_int = self.generateRandomIntValue(size)
        # remove "L" for python2
        hexStr = hex(selected_int).rstrip("L").lstrip("0x") or "0"

    def generateValueByType(self, _type, mode="random"):
        type_obj = self.type_list[_type]
        if type_obj == None:
            logger.error("EVM type not found " + _type)
            return None
        if mode not in self.mode_list:
            logger.error("Incorrect mode for generateValueByType.")
            return None
        
        # seed mode
        if mode == "seed" or _type == "address":
            type_seeds = self.seeds[_type]
            if type_seeds == None or len(type_seeds) == 0:
                logger.error("Cannot find seeds for ", _type)
                # generate random value if seeds are unavailable
                mode = "random"
            else:
                rand_index = random.randint(0, len(type_seeds)-1)
                return type_seeds[rand_index]
        
        # if not seed mode
        if type_obj["type"] == "uint":
            num_size = random.randint(1, type_obj["size"])
            if mode == "min":
                selected_uint = self.generateMinIntValue(0)
            elif mode == "max":
                selected_uint = self.generateMaxIntValue(type_obj["size"])
            elif mode == "random":
                selected_uint = self.generateRandomIntValue(num_size)
            else:
                logger.error("Incorrect mode for generateValueByType.")
                return None
            return selected_uint
        
        elif type_obj["type"] == "int":
            num_size = random.randint(1, type_obj["size"])
            if mode == "min":
                selected_int = (- self.generateMinIntValue(type_obj["size"] - 1))
            elif mode == "max":
                selected_int = self.generateMaxIntValue(type_obj["size"] - 1)
            elif mode == "random":
                selected_int = self.generateRandomIntValue(num_size)
                neg_prob = random.random()
                if neg_prob < 0.5:
                    selected_int = -selected_int
            else:
                logger.error("Incorrect mode for generateValueByType.")
                return None
            return selected_int
        
        elif type_obj["type"] == "address":
            # 'address' generation only support 'seed' mode
            logger.error(
                "Only seed mode is acceptable for address generation.")
            return None
        
        elif type_obj["type"] == "bool":
            bool_prob = random.random()
            if bool_prob < 0.5:
                return 0
            else:
                return 1

        elif type_obj["type"] == "byte":
            num_size = 8
            if mode == "min":
                selected_hex = self.generateMinHexValue(num_size)
            elif mode == "max":
                selected_hex = self.generateMaxHexValue(num_size)
            elif mode == "random":
                selected_hex = self.generateRandomHexValue(num_size)
            else:
                logger.error("Incorrect mode for generateValueByType.")
                return None
            return "0x" + selected_hex

        elif type_obj["type"] == "bytes":
            num_size = type_obj["size"]
            if num_size == None:
                num_size = random.randint(0, 32) * 8
            if mode == "min":
                selected_hex = self.generateMinHexValue(8)
            elif mode == "max":
                selected_hex = self.generateMaxHexValue(num_size)
            elif mode == "random":
                selected_hex = self.generateRandomHexValue(num_size)
            else:
                logger.error("Incorrect mode for generateValueByType.")
                return None
            return "0x" + selected_hex

        elif type_obj["type"] == "array":
            array_len = random.randint(0, 3)
            selected_array = []
            for i in range(array_len):
                selected_array.append(self.generateValueByType(type_obj["element_type"], mode))
            return selected_array

        else:
            logger.error("EVM type not found " + _type)
            return None

    def fuzzByType(self, _type, seed_prob):
        assert(seed_prob >= 0 and seed_prob <= 1)
        rand_prob = random.random()
        if rand_prob < seed_prob:
            return self.generateValueByType(_type, mode="seed")
        else:
            return self.generateValueByType(_type, mode="random")
