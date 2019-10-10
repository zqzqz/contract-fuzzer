import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))
from pyfuzz.fuzzer.fuzzer import Fuzzer
from pyfuzz.fuzzer.interface import Transaction

def test():
    fuzzer = Fuzzer()
    fuzzer.loadContract("/home/qzzhang/Documents/contractfuzzer/contracts/0x5afd842dc2d4dc11fff43d3ac7cc58b6153ded2c#TrumpFarmer.sol", "TrumpFarmer")
    print("contract address:", fuzzer.contractAddress)
    abi = fuzzer.contractAbi
    sender = fuzzer.defaultAccount

    report = fuzzer.contractAnalysisReport
    contract = report.contract
    for function in contract.functions:
        if function.name in ["seedMarket", "getFreeShrimp", "sellEggs"]:
            print(function.name)
            print("read", [str(var) for var in report._function_read(function)])
            print("written", [str(var) for var in report._function_written(function)])
            print("calls", [type(var) for var in function.internal_calls])

    # print("balance", fuzzer.evm.getAccounts())

    # funcHash = abi.functionHashes["SetPass(bytes32)"]
    # tx = Transaction(funcHash, [bytearray(b"\xff\xff")], 10 ** 19, sender, abi.interface[funcHash])
    # trace, state = fuzzer.runOneTx(tx)
    # print("tx", tx)
    # print("trace", [t["op"] for t in trace])
    # print("state", state)
    # print("balance", fuzzer.evm.getAccounts())

    # funcHash = abi.functionHashes["Revoce()"]
    # tx = Transaction(funcHash, [], 0, sender, abi.interface[funcHash])
    # trace, state = fuzzer.runOneTx(tx)
    # print("tx", tx)
    # print("trace", [t["op"] for t in trace])
    # print("state", state)
    # print("balance", fuzzer.evm.getAccounts())

test()