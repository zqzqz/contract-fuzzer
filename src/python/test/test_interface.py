import sys
sys.path.append("..")
from interface import *

def test():
    import evm
    import os
    contract = None
    with open(os.path.join(os.getcwd(), '../../static/testContract.json'), 'r') as f:
        contract = json.load(f)
    abi = ContractAbi(contract)
    print(abi.interface)

    tx = Transaction("23423424", ["1111", "2222"], "1212", "0x123123123123")
    print(tx.payload)

if __name__ == "__main__":
    test()