import evm
from interface import contractAbi, Transaction
import types
import logging


class ArgsPool():
    def __init__(self):
        pass

class Fuzzer():
    def __init__(self, evmEndPoint, maxFuncNum, maxCallNum):
        self.argsPool = ArgsPool()
        self.evm = EvmHandler(evmEndPoint)
        self.contract = None
        self.contractAddress = None
        self.contractAbi = None
        self.maxFuncNum = maxFuncNum
        self.maxCallNum = maxCallNum

    def loadContract(self, source, name):
        self.contract = evm.compile(source, name)
        self.contractAddress = evm.deploy(self.contract)
        self.contractAbi = ContractAbi(self.contract)

    def runOneTx(self, tx):
        if self.contract == None:
            logging.error("Contract have not been loaded.")
            return None
        trace = evm.sendTx(tx.sender, self.contractAbi, tx.value, tx.payload)
        return trace

    def runTxs(self, txList):
        traces = []
        for tx in txList:
            trace.append(self.runOneTx(tx))
        return traces

    def mutate(self, txList):
        pass
        