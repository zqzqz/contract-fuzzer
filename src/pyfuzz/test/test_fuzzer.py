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

def test_exploit(datadir):
    filename = os.path.join(datadir, '0x57a53ffa64204f5f65c44f0179aecc152d68e81b#LetsCooperate.sol')
    fuzzer = Fuzzer()
    fuzzer.loadContract(filename, "LetsCooperate")
    print("Reset...")
    state, seqLen = fuzzer.reset()
    for i in range(100):
        action = randint(0, TRAIN_CONFIG["action_num"]-1)
        print("Action", action)
        state, seqLen, reward, done = fuzzer.step(action)
        fuzzer.printTxList(fuzzer.state.txList)
        print("reward:", reward, "done:", done)
        print("visited:", fuzzer.contractMap[filename]["visited"])

if __name__ == "__main__":
    test()
    # test_exploit("/home/zqz/contracts")