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
    print("state", state.shape)
    print("Mutate...")
    state, seqLen, reward, done = fuzzer.step(0)
    fuzzer.printTxList(fuzzer.state.txList)
    print("state:", state.shape)
    print("visited:", fuzzer.contractMap[filename]["visited"])
    print("seeds:", fuzzer.contractMap[filename]["abi"].typeHandler.seeds)


if __name__ == "__main__":
    test()