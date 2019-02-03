import sys
sys.path.append("..")
from evm import *

def test():
    evm = EvmHandler()
    with open(os.path.join(os.getcwd(), '../../static/Test.sol'), 'r') as f:
        text = f.read()
    print("\ncontract\n")
    print(text)
    print("\nTesting getAccounts:\n")
    accounts = evm.getAccounts()
    print(accounts)
    print("\nTesting compile\n")
    contract = evm.compile(text, "Test")
    print(contract)
    print("\nTesting deploy\n")
    address = evm.deploy(contract)
    print(address)

if __name__ == "__main__":
    test()