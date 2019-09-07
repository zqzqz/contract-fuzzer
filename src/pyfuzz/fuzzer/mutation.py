from pyfuzz.fuzzer.interface import ContractAbi, Transaction
from pyfuzz.fuzzer.action import Action, actionProcessor
from pyfuzz.fuzzer.state import State, StateProcessor
from pyfuzz.analyzer.static_analyzer import AnalysisReport
from pyfuzz.config import TRAIN_CONFIG, FUZZ_CONFIG

import logging
from random import randint, choice

logger = logging.getLogger("Fuzzer")
logger.setLevel(logging.INFO)

class MutationProcessor:

    def __init__(self, contractAbi, analysis_report):
        self.contractAbi = contractAbi
        self.contractAnalysisReport = contractAnalysisReport
        self.criticalFuncHashList = []
        for funcHash in self.contractAbi.funcHashList:
            if self.contractAnalysisReport.func_map[]

    def init_state():
        pass

    def mutate(self, state):
        # action selection
        action = 0
        # mutation
        return mutate_with_action(0)

    def feedback(self, score):
        pass

    def _mutate_with_action(self, state, action):
        txList = state.txList + []
        actionId = action.actionId
        actionArg = action.actionArg
        txHash = None
        if actionArg < 0 or actionArg >= self.maxCallNum:
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

        # manual checks
        # NOTE: only use manual checks without training
        logger.debug("action", actionId, actionArg)
        if not txList[-1]:
            actionArg = len(txList) -1
            actionId = 0
        elif txHash == None:
            actionId = 0
        logger.debug("checked action", actionId, actionArg)

        # modify
        if actionId == 0:
            funcHash = txHash
            if len(self.contractAbi.funcHashList) <= 0 or (len(self.contractAbi.funcHashList) == 1 and txHash in self.contractAbi.funcHashList):
                return None
            # select candidate functions
            for funcHash in self.contractAbi.funcHashList:
                if self._check_taint(txList, funcHash, actionArg):
                    tx = self.contractAbi.generateTx(funcHash, self.contractAbi.accounts[0], seeds)
                    txList[actionArg] = tx
                    break
            for i in range(len(txList)):
                if not 
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
