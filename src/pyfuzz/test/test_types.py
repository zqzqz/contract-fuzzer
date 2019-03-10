import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))
from pyfuzz.evm_types.types import TypeHandler

if __name__ == '__main__':
    typeHandler = TypeHandler()
    print(typeHandler.generateValueByType("uint256", "min"))
    print(typeHandler.generateValueByType("uint256", "max"))
    print(typeHandler.generateValueByType("uint256", "random"))
    print(typeHandler.generateValueByType("uint256", "seed"))