from pyfuzz.evm.evm import EvmHandler
from pyfuzz.fuzzer.interface import ContractAbi, Transaction
from pyfuzz.trainer.model import Action, ActionProcessor, State, StateProcessor
from pyfuzz.fuzzer.trace import TraceAnalyzer, branch_op
from pyfuzz.analyzer.static_analyzer import StaticAnalyzer, AnalysisReport
from pyfuzz.fuzzer.exploit import Exploit
from pyfuzz.config import TRAIN_CONFIG, DIR_CONFIG, FUZZ_CONFIG

import logging
from random import randint, choice
import json
import os

logger = logging.getLogger("Fuzzer")
logger.setLevel(logging.INFO)


class Fuzzer():
    def __init__(self, evmEndPoint=None, opts={}):
        # load config
        self.opts = opts
        if "exploit" not in opts:
            self.opts["exploit"] = False
        if "vulnerability" not in opts:
            self.opts["vulnerability"] = False
        # init evm handler
        if evmEndPoint:
            self.evm = EvmHandler(evmEndPoint)
        else:
            self.evm = EvmHandler()
        # contract properties
        self.filename = None
        self.contract = None
        self.contractAbi = None
        self.contractAnalysisReport = None
        # contract cache. Each element is a dict {"name", "contract", "abi", "report", "visited"}
        self.contractMap = {}
        self.contractAddress = None
        # current state
        self.state = None
        self.seqLen = None
        # configurations
        self.maxFuncNum = TRAIN_CONFIG["max_func_num"]
        self.maxCallNum = TRAIN_CONFIG["max_call_num"]
        self.actionNum = TRAIN_CONFIG["action_num"]
        # state and action processor
        self.stateProcessor = StateProcessor()
        self.actionProcessor = ActionProcessor()
        # execution results
        self.traces = []
        self.report = []
        # eth accounts
        self.accounts = self.evm.getAccounts()
        self.defaultAccount = list(self.accounts.keys())[0]
        # analyzers
        self.traceAnalyzer = TraceAnalyzer()
        self.staticAnalyzer = StaticAnalyzer()
        # for test
        self.counter = 0
        # eth accounts as seeds of type address
        with open(os.path.join(DIR_CONFIG["seed_dir"], 'address.json'), 'w') as f:
            json.dump(list(self.accounts.keys()), f, indent="\t")

    def refreshEvm(self):
        self.evm.reset()

    def loadContract(self, filename, contract_name):
        self.state = None
        self.seqLen = None
        self.traces = []
        self.report = []
        self.counter = 0
        self.filename = filename
        if filename in self.contractMap:
            # the contract is in cache
            self.contract = self.contractMap[filename]["contract"]
            self.contractMap[filename]["abi"] = ContractAbi(self.contract)
            self.contractAbi = self.contractMap[filename]["abi"]
            self.contractAnalysisReport = self.contractMap[filename]["report"]
            return True
        else:
            # try:
            with open(filename, "r") as f:
                source = f.read()
            self.contract = self.evm.compile(source, contract_name)
            self.contractAbi = ContractAbi(self.contract)
            # run static analysis
            self.staticAnalyzer.load_contract(filename, contract_name)
            self.contractAnalysisReport = self.staticAnalyzer.run()
            # set cache
            self.contractMap[filename] = {
                "name": contract_name,
                "contract": self.contract,
                "abi": self.contractAbi,
                "report": self.contractAnalysisReport,
                "visited": set([])
            }
            return True
            # except Exception as e:
            #     logger.error("fuzz.loadContract: {}".format(str(e)))
            #     return False

    def runOneTx(self, tx):
        if self.contract == None:
            logger.error("Contract have not been loaded.")
            return None
        trace = self.evm.sendTx(tx.sender, self.contractAddress,
                                str(tx.value), tx.payload)
        return trace

    def runTxs(self, txList):
        self.contractAddress = self.evm.deploy(self.contract)
        traces = []
        for tx in txList:
            if not tx:
                continue
            tx.updateVisited()
            self.contractMap[self.filename]["abi"].updateVisited(tx.hash)
            trace = self.runOneTx(tx)
            if not trace:
                trace = []
            traces.append(trace)
        return traces

    def reward(self, traces):
        reward, report, jump_pcs = self.traceAnalyzer.run(
            self.traces, traces, self.opts["vulnerability"])
        self.traces = traces

        return reward, report, jump_pcs

    def loadSeed(self, txList, pcs):
        """
        add arguments of a tx list to seeds
        """
        valid_tx_cnt = 0
        for tx in txList:
            if tx:
                valid_tx_cnt += 1
        assert(valid_tx_cnt == len(pcs))

        seeds = self.contractAbi.typeHandler.seeds
        visitedPcList = self.contractMap[self.filename]["visited"]
        j = 0
        for i in range(len(txList)):
            if not txList[i]:
                continue
            if pcs[j].issubset(visitedPcList):
                j += 1
                continue
            self.contractMap[self.filename]["visited"] = visitedPcList.union(
                pcs[j])
            for arg in txList[i].typedArgs:
                if arg[0] not in seeds:
                    seeds[arg[0]] = [arg[1]]
                else:
                    seeds[arg[0]].append(arg[1])

    def mutate(self, state, action):
        txList = state.txList + []
        actionId = action.actionId
        actionArg = action.actionArg
        txHash = None
        if actionArg < 0 or actionArg >= self.maxCallNum:
            return None
        if txList[actionArg]:
            txHash = txList[actionArg].hash

        # modify
        if actionId == 0:
            funcHash = txHash
            if len(self.contractAbi.funcHashList) <= 0 or (len(self.contractAbi.funcHashList) == 1 and txHash in self.contractAbi.funcHashList):
                return None
            attempt = 100
            while funcHash == txHash and attempt > 0:
                funcHash = choice(self.contractAbi.funcHashList)
                attempt -= 1
            tx = self.contractAbi.generateTx(funcHash, self.defaultAccount)
            txList[actionArg] = tx
        elif actionId == 1:
            # modify args
            if txHash == None:
                return None
            txList[actionArg].args = self.contractAbi.generateTxArgs(txHash)
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
                value = self.contractAbi.generateTxValue(txHash)
                attempt -= 1
            txList[actionArg].value = value
        else:
            return None
        return State(state.staticAnalysis, txList)

    def reset(self):
        """
        reset the fuzzer with current contract
        """
        self.counter = 0
        if not self.contract:
            logger.error("Contract not inintialized in fuzzer.")
            return None, None
        self.contractAddress = self.evm.deploy(self.contract)

        self.state = State(self.contractAnalysisReport, [
                           None for i in range(self.maxCallNum)])
        self.traces = []
        self.report = []
        state, seqLen = self.stateProcessor.encodeState(self.state)
        return state, seqLen

    def random_reset(self, datadir):
        """
        randomly select a contract from datadir and reset
        """
        contract_files = os.listdir(datadir)
        filename = choice(contract_files)
        state, seq_len = self.contract_reset(datadir, filename)
        while seq_len == None:
            filename = choice(contract_files)
            state, seq_len = self.contract_reset(datadir, filename)
        return state, seq_len, filename

    def contract_reset(self, datadir, filename):
        """
        reset fuzzer with the given contract file
        """
        assert(filename != None)
        full_filename = os.path.join(datadir, filename)
        # todo: this is only proper for our dataset
        contract_name = filename.split('.')[0].split("#")[-1]
        if self.loadContract(full_filename, contract_name):
            return self.reset()
        else:
            return None, None

    def step(self, action):
        done = 0
        self.counter += 1
        reward = 0
        timeout = 0
        try:
            # testing
            if self.counter >= FUZZ_CONFIG["max_attempt"]:
                timeout = 1
            action = self.actionProcessor.decodeAction(action)
            nextState = self.mutate(self.state, action)
            if not nextState:
                state, seqLen = self.stateProcessor.encodeState(self.state)
                return state, seqLen, reward, done, timeout
            # execute transactions
            traces = self.runTxs(nextState.txList)
            # get reward of executions
            reward, report, pcs = self.reward(traces)
            # bonus for valid mutation
            reward += FUZZ_CONFIG["valid_mutation_reward"]
            # update seeds
            self.loadSeed(nextState.txList, pcs)
            # check whether exploitation happens
            if self.opts["exploit"]:
                self.accounts = self.evm.getAccounts()
                # balance increase
                bal_p = 0
                bal = 0
                for acc in self.accounts.keys():
                    bal_p += int(FUZZ_CONFIG["account_balance"], 16)
                    bal += int(self.accounts[acc], 16)

                if bal > bal_p:
                    reward += FUZZ_CONFIG["exploit_reward"]
                    report.append(Exploit(nextState.txList, bal-bal_p))
                # check the opcode SELFDESTRUCT
                else:
                    for trace in traces:
                        if len(trace) > 0 and trace[-1]["op"] == "SELFDESTRUCT":
                            reward += FUZZ_CONFIG["exploit_reward"]
                            report.append(Exploit(nextState.txList, 0))
                            break
            # testing
            if len(report) > 0:
                done = 1
            # update
            self.state = nextState
            self.traces = traces
            # should exclude repeated reports
            self.report = list(set(self.report + report))
            state, seqLen = self.stateProcessor.encodeState(self.state)
            return state, seqLen, reward, done, timeout
        except Exception as e:
            logger.error("fuzzer.step: {}".format(str(e)))
            state, seqLen = self.stateProcessor.encodeState(self.state)
            return state, seqLen, 0, 0, 1

    def coverage(self):
        jump_cnt = 0
        try:
            code = self.contract["assembly"][".data"]["0"][".code"]
            for op in code:
                if op["name"][:4] in branch_op:
                    jump_cnt += 1
        except:
            pass

        if jump_cnt == 0:
            return 1
        else:
            return len(self.contractMap[self.filename]["visited"]) / jump_cnt

    @staticmethod
    def printTxList(txList):
        print("txList:")
        for i in range(len(txList)):
            if not txList[i]:
                continue
            print("[{}] payload: {}, sender: {}, value: {}, visited: {}, total_visited: {}".format(
                str(i), txList[i].payload, txList[i].sender, txList[i].value, txList[i].tmp_visited, txList[i].total_visited))
