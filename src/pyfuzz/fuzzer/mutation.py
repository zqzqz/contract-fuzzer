from pyfuzz.fuzzer.interface import ContractAbi, Transaction
from pyfuzz.fuzzer.action import Action, ActionProcessor
from pyfuzz.fuzzer.state import State, StateProcessor
from pyfuzz.analyzer.static_analyzer import AnalysisReport
from pyfuzz.config import TRAIN_CONFIG, FUZZ_CONFIG

import logging
from random import random

logger = logging.getLogger("Fuzzer")
logger.setLevel(logging.INFO)

class MutationProcessor:

    def __init__(self, contractAbi, contractAnalysisReport):
        self.contractAbi = contractAbi
        self.contractAnalysisReport = contractAnalysisReport
        self.criticalFuncHashList = []

        # help select functions by weight
        self.func_history = {}
        self.func_history_delta = {}
        for funcHash in self.contractAbi.funcHashList:
            self.func_history[funcHash] = [0,0] # [interesting cases number, none interesting]
            self.func_history_delta[funcHash] = [0,0]
        self.s = 0

    def init_state(self):
        return State(self._gen_txs())

    def mutate(self, state):
        # action selection
        action = 0
        # mutation
        return mutate_with_action(0)

    def feedback(self, score):
        pass

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


    def _random_select_tx(self, hashList):
        assert(len(hashList) > 0)
        thres = []
        score = 0
        for funcHash in hashList:
            if funcHash not in self.func_history:
                raise Exception("wrong func hash")
            score = score + self.func_history[funcHash][0]/((self.func_history[funcHash][0] + self.func_history[funcHash][1]) or 1) + 0.2
            thres.append(score)
        pin = random() * thres[-1]
        for i in range(len(thres)):
            if thres[i] >= pin:
                return hashList[i]
        raise Exception("something wrong")

    def _gen_txs(self):
        txList = [None for i in range(TRAIN_CONFIG["max_call_num"])]
        # get Seeds
        hashList = []
        for tx in txList:
            if not tx:
                continue
            hashList.append(tx.hash)
        seeds = self.contractAbi.getSeeds(hashList)

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
            tx = self.contractAbi.generateTx(selectedHash, None, seeds)
            txList[i] = tx
        return txList

    def _mutate_with_action(self, state, action):
        txList = state.txList + []
        actionId = action.actionId
        actionArg = action.actionArg
        txHash = None
        # NOTE: actionId=0 is disabled
        if actionArg <= 0 or actionArg >= self.maxCallNum:
            logger.error("wrong action")
            return None
        if txList[actionArg]:
            txHash = txList[actionArg].hash

        # get Seeds
        hashList = []
        for tx in txList:
            if not tx:
                continue
            hashList.append(tx.hash)
        seeds = self.contractAbi.getSeeds(hashList)

        # modify
        if actionId == 0:
            # disable 0
            pass
        elif actionId == 1:
            # modify args
            if txHash == None:
                return None
            txList[actionArg].args = self.contractAbi.generateTxArgs(txHash, seeds)
        elif actionId == 2:
            # modify sender
            if txHash == None:
                return None
            sender = state.txList[actionArg].sender
            attempt = 100
            while sender == state.txList[actionArg].sender and attempt > 0:
                randIndex = randint(0, len(self.accounts.keys())-1)
                sender = list(self.accounts.keys())[randIndex]
                attempt -= 1
            txList[actionArg].sender = sender
        elif actionId == 3:
            # modify value
            if txHash == None:
                return None
            if not self.contractAbi.interface[txHash]['payable']:
                # not payable function
                return None
            value = state.txList[actionArg].value
            attempt = 100
            while value == state.txList[actionArg].value and attempt > 0:
                value = self.contractAbi.generateTxValue(txHash, seeds)
                attempt -= 1
            txList[actionArg].value = value
        else:
            return None
        return State(txList)
