import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))
from pyfuzz.fuzzer.generator import InputGenerator
from pyfuzz.fuzzer.interface import ContractAbi, Transaction
from pyfuzz.fuzzer.fuzzer import Fuzzer
from pyfuzz.analyzer.static_analyzer import StaticAnalyzer, AnalysisReport

def test():
    filename = os.path.join(os.path.dirname(__file__), '../test/contracts/Test.sol')
    contract_name = "Test"
    fuzzer = Fuzzer()
    fuzzer.loadContract(filename, contract_name)
    
    contract = fuzzer.getContract(filename)
    processor = InputGenerator(contract["abi"], contract["report"])
    print(processor.generate().txList)

if __name__ == "__main__":
    test()