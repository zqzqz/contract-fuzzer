import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))
from pyfuzz.fuzzer.fuzzer import Fuzzer
from pyfuzz.fuzzer.interface import Transaction

def test():
    fuzzer = Fuzzer()
    fuzzer.loadContract(os.path.join(os.path.dirname(__file__), '/home/zqz/test/contracts/0x0cfA149c0a843e1f8d9bC5C6e6bebf901845CeBE#ENVELOPE.sol'), "ENVELOPE")
    print("contract address:", fuzzer.contractAddress)
    abi = fuzzer.contractAbi
    sender = fuzzer.defaultAccount
    
    print("balance", fuzzer.evm.getAccounts())

    funcHash = abi.functionHashes["SetPass(bytes32)"]
    tx = Transaction(funcHash, [bytearray(b"\xff\xff")], 10 ** 19, sender, abi.interface[funcHash])
    trace, state = fuzzer.runOneTx(tx)
    print("tx", tx)
    print("trace", [t["op"] for t in trace])
    print("state", state)
    print("balance", fuzzer.evm.getAccounts())

    funcHash = abi.functionHashes["Revoce()"]
    tx = Transaction(funcHash, [], 0, sender, abi.interface[funcHash])
    trace, state = fuzzer.runOneTx(tx)
    print("tx", tx)
    print("trace", [t["op"] for t in trace])
    print("state", state)
    print("balance", fuzzer.evm.getAccounts())

test()