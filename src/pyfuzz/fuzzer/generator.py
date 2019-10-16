from pyfuzz.fuzzer.interface import ContractAbi, Transaction
from pyfuzz.fuzzer.state import State
from pyfuzz.analyzer.static_analyzer import AnalysisReport
from pyfuzz.config import FUZZ_CONFIG
from pyfuzz.evm_types.types import fillSeeds, cleanTypeNames, TypeHandler
from pyfuzz.utils.utils import isHexString, isIntString

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
        self.s = 1
        self.state = State(self._gen_blank_txs())
        return self.state

    def fill(self, index, seeds):
        import copy
        assert(self.state and index >=0 and index < len(self.state.txList))
        if self.state.txList[index] == None:
            return
        funcHash = self.state.txList[index].hash
        if funcHash not in self.contractAbi.interface:
            raise Exception("function not found in abi")
        paras = {}
        for i in range(len(self.contractAbi.interface[funcHash]["inputs"])):
            _input = self.contractAbi.interface[funcHash]["inputs"][i]
            _input["index"] = i
            paras[_input["name"]] = _input

        # add seeds
        res_seeds = copy.deepcopy(self.contractAbi.seedMap[funcHash])
        conditions = self.contractAnalysisReport.get_conditions(funcHash)
        # conditions
        for _id in conditions:
            condition = conditions[_id]
            # add seeds of state values
            for s in condition["states"]:
                s_type = cleanTypeNames(s._type)
                if s_type != None:
                    continue
                for d in condition["deps"]:
                    if s == None or d.name not in paras:
                        continue
                    p_type = cleanTypeNames(paras[d.name]["type"])
                    if s_type == p_type:
                        fres_seeds[paras[d.name]["index"]] = illSeeds(s["value"], s_type, res_seeds[paras[d.name]["index"]])
            # constant literal values
            for n in condition["consts"]:
                if not isinstance(n, str):
                    continue
                for d in condition["deps"]:
                    if n == None or d.name not in paras:
                        continue
                    p_type = cleanTypeNames(paras[d.name]["type"])
                    if isHexString(n) and p_type == "bytes32":
                        res_seeds[paras[d.name]["index"]] = fillSeeds(n, p_type, res_seeds[paras[d.name]["index"]])
                    if isIntString(n) and p_type == "uint256":
                        res_seeds[paras[d.name]["index"]] = fillSeeds(int(n,10), p_type, res_seeds[paras[d.name]["index"]])
        # other seeds
        for p in paras:
            type_str = paras[p]["type"]     
            if type_str in seeds:
                for value in seeds[type_str]:
                    res_seeds[paras[p]["index"]] = fillSeeds(value, type_str, res_seeds[paras[p]["index"]])

        # generate transaction
        tx = self.contractAbi.generateTx(funcHash, res_seeds)
        self.state.txList[index] = tx
        return self.state         

    def feedback(self, score):
        assert(self.state != None)
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
        try:
            assert(index >= 0 and index < len(txList))
            txHash = txList[index].hash

            if index == len(txList) - 1:
                return self.contractAnalysisReport.is_function_critical(txHash)
            else:
                f = self.contractAnalysisReport.get_function(txHash)
                write_set = set(self.contractAnalysisReport._function_written(f))
                read_set = set([])
                for i in range(index + 1, len(txList)):
                    tmpHash = txList[i].hash
                    f = self.contractAnalysisReport.get_function(tmpHash)
                    if f == None:
                        raise False
                    read_set = read_set.union(self.contractAnalysisReport._function_read(f))
                return (len(read_set.intersection(write_set)) > 0)
        except Exception as e:
            import traceback
            logger.error("generator._check_tx: {} {}".format(str(e), traceback.format_exc()))
            return False

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
        txList = [None for i in range(FUZZ_CONFIG["max_call_num"])]

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
            seeds = self.contractAbi.seedMap[selectedHash]
            tx = self.contractAbi.generateTx(selectedHash, seeds)
            txList[i] = tx
        return txList
