import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))
from pyfuzz.utils.utils import *

if __name__ == '__main__':
    print(hexToUint8("0xc87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3", 32))
    print(hexToBinary("0xc87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3", 256))