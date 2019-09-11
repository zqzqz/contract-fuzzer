import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))
from pyfuzz.fuzzer.mutation import MutationProcessor
from pyfuzz.fuzzer.interface import ContractAbi, Transaction
from pyfuzz.fuzzer.fuzzer import Fuzzer
from pyfuzz.analyzer.static_analyzer import StaticAnalyzer, AnalysisReport

def test():
    filename = os.path.join(os.path.dirname(__file__), '../test/contracts/Test.sol')
    contract_name = "Test"
    fuzzer = Fuzzer()
    fuzzer.loadContract(filename, contract_name)
    
    contract = fuzzer.getContract(filename)
    processor = MutationProcessor(contract["abi"], contract["report"])
    print(processor.init_state().txList)

if __name__ == "__main__":
    test()