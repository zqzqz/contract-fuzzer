import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))
from pyfuzz.evm import EvmHandler
from pyfuzz.fuzzer.interface import Transaction
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
    print(contract)
    print("\nTesting deploy\n")
    address = evm.deploy(contract)
    print(address)
    print("\nTesting sendTx\n")
    trace = evm.sendTx(list(accounts.keys())[0], address, "10000000000", contract["functionHashes"]["test1(uint256)"] + "0" * 32)
    for t in trace:
        print(t["op"], end=" ")
    print("\nTesting getAccounts:\n")
    accounts = evm.getAccounts()
    print(accounts)


def test_exploit(datadir):
    filename = os.path.join(datadir, '0x6f905E47d3e6A9Cc286b8250181Ee5A0441Acc81#PRESENT_1_ETH.sol')
    evm = EvmHandler()
    with open(filename, 'r') as f:
        text = f.read()
    print("contract loaded")
    contract = evm.compile(text, "PRESENT_1_ETH")
    print("compiled")
    address = evm.deploy(contract)
    print("deployed")
    accounts = evm.getAccounts()
    account = list(accounts.keys())[0]
    balance = accounts[account]
    trace = evm.sendTx(account, address, "0", contract["functionHashes"]["PutGift(address)"] + eth_abi.encode_abi(["address"], [account]).hex())
    print("trace:", trace[-1]["op"])
    trace = evm.sendTx(account, address, "0", contract["functionHashes"]["GetGift()"])
    print("trace:", trace[-1]["op"])
    accounts = evm.getAccounts()
    balance_1 = accounts[account]
    print("balance increment:", int(balance_1, 16) - int(balance, 16))

if __name__ == "__main__":
    test()
    # "/home/zqz/contracts" is my directory
    # test_exploit("/home/zqz/contracts")