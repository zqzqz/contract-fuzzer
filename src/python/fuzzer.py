import evm
from interface import contractAbi, Transaction
import types

class ArgsPool():
    def __init__(self):
        pass

class Fuzzer():
    def __init__(self, evmEndPoint):
        self.argsPool = ArgsPool()
        self.evm = EvmHandler(evmEndPoint)
        self.contract = None
        self.contractAddress = None

    def runOnce(self, tx):
        pass