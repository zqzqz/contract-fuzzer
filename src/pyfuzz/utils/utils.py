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

def binaryToHex(binary, size=None):
    assert(size == None or size > 0)
    if size != None:
        binary = np.append(binary, np.array([0] * (size - len(binary)), dtype=np.uint8))
    if len(binary) % 4 != 0:
        binary = np.append(binary, np.array([0] * (4 - (len(binary) % 4)), dtype=np.uint8))
    hexStr = ""
    for i in range(0, len(binary), 4):
        sub_binary = binary[i:i+4]
        sub_num = 0
        for k in sub_binary:
            sub_num = sub_num * 2 + k
        hexStr += hex(sub_num).rstrip("L").lstrip("0x") or "0"
    return hexStr

def negativeValue(value, size):
    binary = hexToBinary(value, size)
    binary[0] = 0
    for i in range(len(binary)):
        if binary[i] == 0:
            binary[i] = 1
        else:
            binary[i] = 0
    for i in range(len(binary)):
        binary[-(i+1)] += 1
        if binary[-(i+1)] >= 2:
            binary[-(i+1)] = 0
            continue
        else:
            break
    hexStr = binaryToHex(binary, size)
    return hexStr


def formatHexValue(value, size, flag=1):
    if len(value) > size // 4:
        if flag:
            return value[-size:]
        else:
            return value[:size]
    elif len(value) < size // 4:
        if flag:
            return "0" * (size // 4 - len(value)) + value
        else:
            return value + "0" * (size // 4 - len(value))
    else:
        return value

def removeHexPrefix(hexStr):
    assert(isHexString(hexStr))
    return hexStr.replace("0x", "")


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

def valueToHex32(value):
    if isHexString(value):
        _value = removeHexPrefix(value)
        return hex256ToHex32(_value)
    elif isinstance(value, int):
        _value = hex(value).rstrip("L").lstrip("-").lstrip("0x") or "00"
        if value < 0:
            _value = negativeValue(_value, 256)
        return hex256ToHex32(_value)

def intToHex(num, token_size):
    assert(isinstance(num, int))
    hex_num = hex(num).rstrip("L").lstrip("0x") or "0"
    hex_len = token_size // 4
    if len(hex_num) < hex_len:
        hex_num = "0" * (hex_len - len(hex_num)) + hex_num
    return hex_num[-hex_len:]

def intListToHexString(int_list, token_size):
    hex_str = ""
    for i in int_list:
        hex_str += intToHex(i, token_size)
    return hex_str

def intToOnehot(num, token_size):
    assert(num >= 0)
    res = [0 for i in range(token_size)]
    if num >= token_size:
        num = token_size
    if num > 0:
        res[token_size - num] = 1
    return res

def experimentDirectory(base_dir, opts):
    assert(isinstance(opts, dict))
    values = list(opts.values())
    label = 0
    for value in values:
        label = label * 2 + int(value)
    return base_dir + str(label)


            