import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))
from pyfuzz.evm import EvmHandler
from pyfuzz.fuzzer.interface import Transaction
from pyfuzz.fuzzer.detector.detector import Detector, Vulnerability
import json

evm = EvmHandler()
detector = Detector({"vulnerability": True})

def test_vulnerability(name):
    print("Testing", name)
    with open(os.path.join(os.path.dirname(__file__), '../test/contracts/'+name+'.sol'), 'r') as f:
        text = f.read()
    accounts = evm.getAccounts()
    contract = evm.compile(text, "Test")
    address = evm.deploy(contract)
    trace = evm.sendTx(list(accounts.keys())[1], address, "0", contract["functionHashes"][name+"()"])
    for t in trace:
        print(t["op"], end=" ")
    print()
    # with open(os.path.join(os.path.dirname(__file__), '../test/contracts/'+name+'Trace.json'), 'w') as f:
    #     json.dump(trace, f, indent=4)
    vulns = detector.run([trace])
    for vuln in vulns:
        print(str(vuln))

if __name__ == "__main__":
    test_vulnerability("TimestampDependency")
    test_vulnerability("BlockNumberDependency")
    test_vulnerability("UnhandledException")
    test_vulnerability("Reentrancy")