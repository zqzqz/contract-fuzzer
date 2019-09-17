from pyfuzz.fuzzer.interface import ContractAbi, Transaction
from pyfuzz.fuzzer.action import Action, ActionProcessor
from pyfuzz.fuzzer.state import State, StateProcessor
from pyfuzz.analyzer.static_analyzer import AnalysisReport
from pyfuzz.config import TRAIN_CONFIG, FUZZ_CONFIG

import logging
from random import random

logger = logging.getLogger("Fuzzer")
logger.setLevel(logging.INFO)

class InputGenerator:

    def __init__(self, contractAbi, contractAnalysisReport):
        # external
        self.contractAbi = contractAbi
        self.contractAnalysisReport = contractAnalysisReport
        self.criticalFuncHashList = []
        
        # const
        self.stage_capacity = 50

        # dynamic
        # help select functions by weight
        self.func_history = {}
        self.func_history_delta = {}
        for funcHash in self.contractAbi.funcHashList:
            self.func_history[funcHash] = [0,0] # [interesting cases number, none interesting]
            self.func_history_delta[funcHash] = [0,0]
        self.s = 0
        self.counter = 0
        self.state = None

    def generate(self):
        assert(self.s == 0)
        self.s = 1
        self.state = State(self._gen_blank_txs())

    def fill(self, index, state, seeds):
        pass

    def feedback(self, score):
        assert(self.s == 1 and self.state != None)
        self.s = 0
        self.counter += 1
        
        for tx in self.state.txList:
            if tx == None:
                continue
            if score:
                self.func_history_delta[tx.hash][0] += 1
            else:
                self.func_history_delta[tx.hash][1] += 1
        
        if self.counter >= self.stage_capacity:
            self.clear_stage()

    def clear_stage(self):
        self.counter = 0
        for funcHash in self.contractAbi.funcHashList:
            self.func_history[funcHash][0] += self.func_history_delta[funcHash][0]
            self.func_history[funcHash][1] += self.func_history_delta[funcHash][1]
            self.func_history_delta[funcHash] = [0, 0]

    def _check_tx(self, txList, index):
        # the requirements of a transaction in sequence
        assert(index >= 0 and index < len(txList))
        txHash = txList[index].hash

        if index == len(txList) - 1:
            return self.contractAnalysisReport.is_function_critical(txHash)
        else:
            f = self.contractAnalysisReport.get_function(txHash)
            if f == None:
                raise Exception("cannot not find the function in analysis report")
            write_set = set(f._vars_written)
            read_set = set([])
            for i in range(index + 1, len(txList)):
                tmpHash = txList[i].hash
                f = self.contractAnalysisReport.get_function(tmpHash)
                if f == None:
                    raise Exception("cannot not find the function in analysis report")
                read_set = read_set.union(f._vars_read)
            return (len(read_set.intersection(write_set)) > 0)

    def _func_weight(self, funcHash):
        return self.func_history[funcHash][0]/((self.func_history[funcHash][0] + self.func_history[funcHash][1]) or 1) + 0.2

    def _random_select_tx(self, hashList):
        assert(len(hashList) > 0)
        thres = []
        score = 0
        for funcHash in hashList:
            if funcHash not in self.func_history:
                raise Exception("wrong func hash")
            score = score + self._func_weight(funcHash)
            thres.append(score)
        pin = random() * thres[-1]
        for i in range(len(thres)):
            if thres[i] >= pin:
                return hashList[i]
        raise Exception("something wrong")

    def _gen_blank_txs(self):
        txList = [None for i in range(TRAIN_CONFIG["max_call_num"])]

        if len(self.contractAbi.funcHashList) <= 0:
            raise Exception("wrong abi: no available functions to select")

        # generate tx from rear
        for i in range(len(txList)-1, -1, -1):
            # select candidate functions
            candidates = []
            for funcHash in self.contractAbi.funcHashList:
                txList[i] = Transaction(hash=funcHash)
                if self._check_tx(txList, i):
                    candidates.append(funcHash)
            if len(candidates) == 0:
                for i in range(i+1):
                    txList[i] = None
                return txList
            selectedHash = self._random_select_tx(candidates)
            tx = self.contractAbi.generateTx(selectedHash, None)
            txList[i] = tx
        return txList