import logging
import os, re
import codecs
import random
import json
import string

from pyfuzz.config import DIR_CONFIG
from pyfuzz.utils.utils import removeHexPrefix, isHexString

logger = logging.getLogger("types")
logger.setLevel(logging.INFO)

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

type_list["bytes"] = {"type": "bytes", "size": 256}
type_list["payment"] = {"type": "uint", "size": 128}
type_list["string"] = {"type": "string", "size": None}


mode_list = [
    "min",
    "max",
    "random",
    "seed"
]

seed_dir = DIR_CONFIG["seed_dir"]

def isType(value, _type):
    if _type["type"] == "uint":
        return isinstance(value, int) and value >= 0 and value < 2**_type["size"]
    elif _type["type"] == "int":
        return isinstance(value, int) and value >= -2**(_type["size"]-1) and value < 2**(_type["size"]-1)
    elif _type["type"] == "byte":
        return isinstance(value, str) and re.match("^[0-9a-fA-F]{2}$", value)
    elif _type["type"] == "bytes":
        return isinstance(value, str) and re.match("^[0-9a-fA-F]*$", value) and len(value) % 2 == 0 and len(value) <= _type["size"] // 4
    elif _type["type"] == "bool":
        return isinstance(value, bool)
    elif _type["type"] == "address":
        return isinstance(value, str) and re.match("^0x[0-9a-fA-F]{40}$", value)
    elif _type["type"] == "string":
        return isinstance(value, str)
    else:
        return False

# only implement hex string to types
def castTypes(value, _type):
    if not isinstance(value, str):
        return None
    
    hexStr = removeHexPrefix(value)
    i = 0
    while i < len(hexStr):
        if hexStr[i] != "0":
            break
    hexStr = hexStr[i:]
    if len(hexStr) % 2 > 0:
        hexStr = "0" + hexStr
    
    if _type["type"] == "uint":
        return int(hexStr, 16)
    elif _type["type"] == "int":
        return int(hexStr, 16)
    elif _type["type"] == "byte":
        return hexStr
    elif _type["type"] == "bytes":
        return hexStr
    elif _type["type"] == "bool":
        if int(hexStr, 16) == 0:
            return False
        else:
            return True
    elif _type["type"] == "address":
        if len(hexStr) < 40:
            hexStr = "0x" + "0" * (40 - len(hexStr)) + hexStr
        return hexStr
    elif _type["type"] == "string":
        try:
            return bytes.fromhex(hexStr).decode('utf-8')
        except:
            return None
    else:
        return None

def cleanTypeNames(type_str):
    if type_str == "uint":
        return "uint256"
    elif type_str == "int":
        return "int256"
    elif type_str == "bytes":
        return "bytes32"
    elif type_str in type_list:
        return type_str
    else:
        return None


def fillSeeds(value, type_str, seeds):
    try:
        raw_label = False
        if isHexString(value):
            raw_label = True

        type_str = cleanTypeNames(type_str)
        if not type_str:
            return

        if type_str not in type_list or type_str not in seeds:
            return

        _type = type_list[type_str]
        if raw_label:
            value = castTypes(value, _type)
        if isType(value, _type):
            seeds[type_str].append(value)
        return seeds
    except Exception as e:
        return seeds

class TypeHandler():
    def __init__(self, _seed_dir=seed_dir, _type_list=type_list, _mode_list=mode_list):
        self.seeds = {}
        self.type_list = _type_list
        self.mode_list = _mode_list
        for _type in list(self.type_list.keys()):
            if type_list[_type]["type"] == "array":
                continue
            json_file = os.path.join(_seed_dir, _type + ".json")
            if os.path.isfile(json_file):
                with open(json_file, "r") as f:
                    self.seeds[_type] = list(json.load(f))
            else:
                if type_list[_type]["type"] == "uint" or type_list[_type]["type"] == "int":
                    self.seeds[_type] = [
                        0,
                        1
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
        return res or "0"

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
        return res or "0"

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
        return hexStr

    def generateRandomString(self, size):
        slen = size // 8
        return ''.join(random.sample(string.printable, slen))

    def generateValueByType(self, _type, seeds, mode="random"):
        type_obj = self.type_list[_type]
        if type_obj == None:
            logger.error("EVM type {} not found ".format(_type))
            raise Exception("generator type error")
        if mode not in self.mode_list:
            logger.error("Incorrect mode for generateValueByType.")
            raise Exception("generator type error")
        
        # seed mode
        if (mode == "seed" or _type == "address") and type_obj["type"] != "array":
            type_seeds = seeds[_type]
            if type_seeds == None or len(type_seeds) == 0:
                # generate random value if seeds are unavailable
                mode = "random"
            else:
                # allocate the default account with larger probability
                if _type == "address":
                    if random.random() < 0.8:
                        return type_seeds[0]
                rand_index = random.randint(0, len(type_seeds)-1)
                return type_seeds[rand_index]
        
        # if not seed mode
        if type_obj["type"] == "uint":
            if _type == "payment":
                num_size = random.randint(50, 80)
            else:
                num_size = random.randint(1, type_obj["size"])
            if mode == "min":
                selected_uint = self.generateMinIntValue(0)
            elif mode == "max":
                selected_uint = self.generateMaxIntValue(type_obj["size"])
            elif mode == "random":
                selected_uint = self.generateRandomIntValue(num_size)
            else:
                logger.error("Incorrect mode for generateValueByType.")
                raise Exception("generator type error")
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
                raise Exception("generator type error")
            return selected_int
        
        elif type_obj["type"] == "address":
            # 'address' generation only support 'seed' mode
            logger.error(
                "Only seed mode is acceptable for address generation.")
            raise Exception("generator type error")
        
        elif type_obj["type"] == "bool":
            bool_prob = random.random()
            if bool_prob < 0.5:
                return False
            else:
                return True

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
                raise Exception("generator type error")
            return bytearray.fromhex(selected_hex)

        elif type_obj["type"] == "bytes":
            num_size = type_obj["size"]
            if num_size == None:
                num_size = random.randint(0, 32) * 8
            if mode == "min":
                selected_hex = self.generateMinHexValue(num_size)
            elif mode == "max":
                selected_hex = self.generateMaxHexValue(num_size)
            elif mode == "random":
                selected_hex = self.generateRandomHexValue(num_size)
            else:
                logger.error("Incorrect mode for generateValueByType.")
                raise Exception("generator type error")
            return bytearray.fromhex(selected_hex)

        elif type_obj["type"] == "string":
            num_size = random.randint(0, 32) * 8
            if mode == "min":
                selected_str = self.generateRandomString(num_size)
            elif mode == "max":
                selected_str = self.generateRandomString(num_size)
            elif mode == "random":
                selected_str = self.generateRandomString(num_size)
            else:
                logger.error("Incorrect mode for generateValueByType.")
                raise Exception("generator type error")
            return selected_str

        elif type_obj["type"] == "array":
            array_len = random.randint(0, 3)
            selected_array = []
            for i in range(array_len):
                selected_array.append(self.generateValueByType(type_obj["element_type"], seeds, mode))
            return selected_array

        else:
            logger.error("EVM type not found " + _type)
            raise Exception("generator type error")

    def fuzzByType(self, _type, seed_prob, seeds):
        assert(seed_prob >= 0 and seed_prob <= 1)
        if seeds == None:
            seeds = self.seeds

        rand_prob = random.random()
        if rand_prob < seed_prob:
            return self.generateValueByType(_type, seeds, mode="seed")
        else:
            return self.generateValueByType(_type, seeds, mode="random")
