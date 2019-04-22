import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))
from pyfuzz.evm import EvmHandler
from pyfuzz.fuzzer.interface import Transaction
from pyfuzz.fuzzer.trace import TraceAnalyzer
from pyfuzz.fuzzer.detector.detector import Detector
import eth_abi

def test():
    evm = EvmHandler()
    with open(os.path.join(os.path.dirname(__file__), '../test/contracts/Test.sol'), 'r') as f:
        text = f.read()
    print("\ncontract\n")
    print(text)
    print("\nTesting getAccounts:\n")
    accounts = evm.getAccounts()
    print(accounts)
    print("\nTesting compile\n")
    contract = evm.compile(text, "Test")
    print("\nTesting deploy\n")
    address = evm.deploy(contract)
    print(address)
    print("\nTesting sendTx\n")
    trace = evm.sendTx(list(accounts.keys())[0], address, "0", contract["functionHashes"]["test1(uint256)"] + "0" * 32)
    for t in trace:
        print(t["op"], end=" ")
    print("\nTesting getAccounts:\n")
    accounts = evm.getAccounts()
    print(accounts)

def test_compile(datadir):
    evm = EvmHandler()
    for _filename in os.listdir(datadir):
        contract_name = _filename.split('.')[0].split('#')[1]
        filename = os.path.join(datadir, _filename)
        with open(filename, 'r') as f:
            text = f.read()
        print(_filename)
        contract = evm.compile(text, contract_name)


def test_vulnerability(datadir):
    filename = "0x3e84512f277A5081B9209831C51bCe665035D9DB#TheGame.sol"
    name = filename.split('.')[0].split('#')[1]
    filename = os.path.join(datadir, filename)
    evm = EvmHandler()
    with open(filename, 'r') as f:
        text = f.read()
    print("contract loaded")
    contract = evm.compile(text, name)
    print("compiled")
    address = evm.deploy(contract)
    print("deployed")
    accounts = evm.getAccounts()
    account = list(accounts.keys())[0]
    balance = accounts[account]
    traces = []
    trace = evm.sendTx(account, address, "0", contract["functionHashes"]["contribute_toTheGame()"], {"revert": True})
    print("trace:", [t["op"] for t in trace])
    traces.append(trace)
    detector = Detector({"vulnerability": True})
    report = detector.run(traces)
    print(report)

def test_exploit(datadir):
    filename = "0x8c2ee56d97c010714c11a48d7a745a641eb4d1f9#MultiSendEth.sol"
    name = filename.split('.')[0].split('#')[1]
    filename = os.path.join(datadir, filename)
    evm = EvmHandler()
    with open(filename, 'r') as f:
        text = f.read()
    print("contract loaded")
    contract = evm.compile(text, name)
    print("compiled")
    address = evm.deploy(contract)
    print("deployed")
    accounts = evm.getAccounts()
    account = list(accounts.keys())[0]
    balance = accounts[account]
    trace = evm.sendTx(account, address, "100", "")
    print("trace:", [t["op"] for t in trace])
    trace = evm.sendTx(account, address, "0", contract["functionHashes"]["multiSendEth(uint256,address[])"] + eth_abi.encode_abi(["uint256", "address[]"], [100, [account, account]]).hex())
    print("trace:", [t["op"] for t in trace])
    accounts = evm.getAccounts()
    balance_1 = accounts[account]
    print("balance increment:", int(balance_1, 16) - int(balance, 16))

if __name__ == "__main__":
    # test()
    # test_compile("/home/zqz/teether_contract")
    test_exploit("/home/zqz/teether_contract")
    # test_vulnerability("/home/zqz/contracts")