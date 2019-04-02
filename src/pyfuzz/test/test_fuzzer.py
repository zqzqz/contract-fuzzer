import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))
from pyfuzz.fuzzer.fuzzer import Fuzzer
from pyfuzz.config import DIR_CONFIG, TRAIN_CONFIG
from random import randint

def test():
    filename = os.path.join(os.path.dirname(__file__), '../test/contracts/Test.sol')
    fuzzer = Fuzzer()
    fuzzer.loadContract(filename, "Test")
    print("Reset...")
    state, seqLen = fuzzer.reset()
    fuzzer.printTxList(fuzzer.state.txList)
    print("state", state.shape)
    for i in range(TRAIN_CONFIG["action_num"]):
        print("Mutate...")
        state, seqLen, reward, done = fuzzer.step(i)
        fuzzer.printTxList(fuzzer.state.txList)
        print("state:", state.shape)
        print("visited:", fuzzer.contractMap[filename]["visited"])

def test_exploit(datadir, filename):
    name = filename.split('.')[0].split('#')[1]
    filename = os.path.join(datadir, filename)
    fuzzer = Fuzzer(opts={"exploit": True})
    fuzzer.loadContract(filename, name)
    print("Reset...")
    state, seqLen = fuzzer.reset()
    for i in range(10):
        action = randint(0, TRAIN_CONFIG["action_num"]-1)
        print("Action", action)
        state, seqLen, reward, done = fuzzer.step(action)
        fuzzer.printTxList(fuzzer.state.txList)
        print("reward:", reward, "done:", done)
        print("visited:", fuzzer.contractMap[filename]["visited"])
        print("accounts:", fuzzer.accounts)

if __name__ == "__main__":
    # test()
    test_exploit("/home/zqz/contracts", "0x1ac1c4c67181bb4d3c0a7d9dd2cda5d9692a364d#Boom.sol")
    # test_exploit("/home/zqz/contracts", "0xAa4fD1781246F0B9A63921F7AEe292311EA05Bf7#for_mikle.sol")