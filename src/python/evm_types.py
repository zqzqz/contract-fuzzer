import logging
import os
import codecs

# EVM Types
typeList = {
    "uint256": {
        "type": "number",
        "size": 256
    },

    "payment": {
        "type": "number",
        "size": 64
    },

    "address": {
        "type": "address",
        "size": 160
    }
}

modeList = [
    "min",
    "max",
    "random"
]


def generateAllZeroValue(size):
    return "0" * (size // 4)


def generateAllOneValue(size):
    return "f" * (size // 4)


def generateRandomValue(size):
    return codecs.encode(os.urandom(size // 8), 'hex').decode()


"""
    Description: Generate a hex string given specific evm type.
    Modes: min (all zero value), random (random value), max (maximum value)
"""


def generateValueByType(_type, mode="random"):
    typeObj = typeList[_type]
    if typeObj == None:
        logging.error("EVM type not found " + _type)
        return None
    if mode not in modeList:
        logging.error("Incorrect mode for generateValueByType.")
        return None
    # which type
    if typeObj["type"] == "number":
        if mode == "min":
            return generateAllZeroValue(typeObj["size"])
        elif mode == "max":
            return generateAllOneValue(typeObj["size"])
        elif mode == "random":
            return generateRandomValue(typeObj["size"])
        else:
            logging.error("Incorrect mode for generateValueByType.")
            return None
    else:
        logging.error("EVM type not found " + _type)
        return None
