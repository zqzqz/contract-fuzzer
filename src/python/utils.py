import logging
import re
import numpy as np


def hexToUint8(hexStr, size=None):
    assert(size == None or size > 0)
    hexStr = removeHexPrefix(hexStr)
    uintArr = np.frombuffer(bytes.fromhex(hexStr), dtype=np.uint8)
    if size == None:
        return uintArr
    if uintArr.shape[0] > size:
        uintArr = uintArr[:size]
    elif uintArr.shape[0] < size:
        uintArr = np.append(uintArr, np.zeros(shape=[size-uintArr.shape[0]], dtype=np.uint8))
    return uintArr

def removeHexPrefix(hexStr):
    assert(isHexString(hexStr))
    return hexStr.replace("0x", "")


def isHexString(hexStr):
    if re.match("^(0x)?[0-9a-fA-F]*$", hexStr):
        return True