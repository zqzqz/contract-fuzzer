import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))
from pyfuzz.evm import EvmHandler
from pyfuzz.fuzzer.interface import Transaction
from pyfuzz.fuzzer.detector.detector import Detector, Vulnerability
import json

def timestamp_dependency():
    evm = EvmHandler()
    with open(os.path.join(os.path.dirname(__file__), '../test/contracts/TimestampDependency.sol'), 'r') as f:
        text = f.read()
    accounts = evm.getAccounts()
    contract = evm.compile(text, "Test")
    address = evm.deploy(contract)
    trace = evm.sendTx(list(accounts.keys())[1], address, "0", contract["functionHashes"]["TimestampDependency()"])
    for t in trace:
        print(t["op"], end=" ")
    print()
    # with open(os.path.join(os.path.dirname(__file__), '../test/contracts/TimestampDependencyTrace.json'), 'w') as f:
    #     json.dump(trace, f, indent=4)
    detector = Detector()
    vulns = detector.run([trace])
    for vuln in vulns:
        print(str(vuln))

def block_number_dependency():
    evm = EvmHandler()
    with open(os.path.join(os.path.dirname(__file__), '../test/contracts/BlockNumberDependency.sol'), 'r') as f:
        text = f.read()
    accounts = evm.getAccounts()
    contract = evm.compile(text, "Test")
    address = evm.deploy(contract)
    trace = evm.sendTx(list(accounts.keys())[1], address, "0", contract["functionHashes"]["BlockNumberDependency()"])
    for t in trace:
        print(t["op"], end=" ")
    print()
    with open(os.path.join(os.path.dirname(__file__), '../test/contracts/BlockNumberDependencyTrace.json'), 'w') as f:
        json.dump(trace, f, indent=4)
    detector = Detector()
    vulns = detector.run([trace])
    for vuln in vulns:
        print(str(vuln))

if __name__ == "__main__":
    timestamp_dependency()
    block_number_dependency()