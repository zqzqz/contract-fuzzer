import sys
sys.path.append("..")
from evm_types import *

if __name__ == '__main__':
    typeHandler = TypeHandler()
    print(typeHandler.generateValueByType("uint256", "min"))
    print(typeHandler.generateValueByType("uint256", "max"))
    print(typeHandler.generateValueByType("uint256", "random"))
    print(typeHandler.generateValueByType("uint256", "seed"))