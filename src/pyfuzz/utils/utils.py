import logging
import re
import numpy as np

hexCode = {
    "0": [0, 0, 0, 0],
    "1": [0, 0, 0, 1],
    "2": [0, 0, 1, 0],
    "3": [0, 0, 1, 1],
    "4": [0, 1, 0, 0],
    "5": [0, 1, 0, 1],
    "6": [0, 1, 1, 0],
    "7": [0, 1, 1, 1],
    "8": [1, 0, 0, 0],
    "9": [1, 0, 0, 0],
    "a": [1, 0, 1, 0],
    "b": [1, 0, 1, 1],
    "c": [1, 1, 0, 0],
    "d": [1, 1, 0, 0],
    "e": [1, 1, 1, 0],
    "f": [1, 1, 1, 1],
}

def hexToUint8(hexStr, size=None):
    assert(size == None or size > 0)
    hexStr = removeHexPrefix(hexStr)
    assert(isHexString(hexStr))
    uintArr = np.frombuffer(bytes.fromhex(hexStr), dtype=np.uint8)
    if size == None:
        return uintArr
    if uintArr.shape[0] > size:
        uintArr = uintArr[:size]
    elif uintArr.shape[0] < size:
        uintArr = np.append(uintArr, np.zeros(shape=[size-uintArr.shape[0]], dtype=np.uint8))
    return uintArr

def hexToBinary(hexStr, size=None):
    assert(size == None or size > 0)
    hexStr.lower()
    hexStr = removeHexPrefix(hexStr)
    assert(isHexString(hexStr))
    uintArr = np.array([], dtype=np.uint8)
    if size == None:
        size = 0xffffffff
    count = 0
    while uintArr.shape[0] < size:
        if count >= len(hexStr):
            uintArr = np.append(uintArr, hexCode["0"])
        else:
            uintArr = np.append(uintArr, hexCode[hexStr[count]])
        count += 1
    return uintArr

def removeHexPrefix(hexStr):
    assert(isHexString(hexStr))
    return hexStr.replace("0x", "")


def isHexString(hexStr):
    if re.match("^(0x)?[0-9a-fA-F]*$", hexStr):
        return True

def hex256ToHex32(hexStr):
    assert(isHexString(hexStr))
    if len(hexStr) >= 6:
        res = hexStr[:6]
        power = (len(hexStr) - 6) * 4
    else:
        res = "0" * (6 - len(hexStr)) + hexStr
        power = 0
    hex_power = hex(power).rstrip("L").lstrip("0x") or "00"
    if len(hex_power) < 2:
        hex_power = "0" * (2 - len(hex_power)) + hex_power
    res += hex_power[-2:]
    assert(len(res) == 8)
    return res

def intToHex(num, token_size):
    assert(isinstance(num, int))
    hex_num = hex(num).rstrip("L").lstrip("0x") or "0"
    hex_len = token_size // 4
    if len(hex_num) < hex_len:
        hex_power = "0" * (hex_len - len(hex_num)) + hex_num
    return hex_num[-hex_len:]

def intListToHexString(int_list, token_size):
    hex_str = ""
    for i in int_list:
        hex_str += intToHex(i, token_size)
    return hex_str