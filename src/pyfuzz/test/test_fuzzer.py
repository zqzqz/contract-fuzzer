import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))
from pyfuzz.fuzzer.fuzzer import Fuzzer

def test():
    filename = os.path.join(os.path.dirname(__file__), '../test/contracts/Test.sol')
    fuzzer = Fuzzer()
    fuzzer.loadContract(filename, "Test")
    print("Reset...")
    state, seqLen = fuzzer.reset()
    fuzzer.printTxList(fuzzer.state.txList)
    print(state)
    print("Mutate...")
    state, seqLen, reward, done = fuzzer.step(1)
    fuzzer.printTxList(fuzzer.state.txList)
    print(state)


if __name__ == "__main__":
    test()