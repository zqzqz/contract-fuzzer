import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))
from pyfuzz.fuzzer.interface import *

def test():
    contract = None
    with open(os.path.join(os.path.dirname(__file__), '../../static/test/testContract.json'), 'r') as f:
        contract = json.load(f)
    abi = ContractAbi(contract)
    print(abi.interface)

    func_hash = contract["functionHashes"]["test1(uint256)"]
    tx = Transaction(func_hash, [12345], "1212", "0x123123123123", abi.interface[func_hash])
    print(tx.payload)

if __name__ == "__main__":
    test()