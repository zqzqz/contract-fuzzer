from pyfuzz.evm.evm import *
from pyfuzz.fuzzer.interface import ContractAbi, Transaction
from pyfuzz.trainer.model import *
from pyfuzz.fuzzer.trace import *
from pyfuzz.analyzer.static_analyzer import *
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
            self.opts["exploit"] = True
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
            self.contractAbi = self.contractMap[filename]["abi"]
            self.analysisAnalysisReport = self.contractMap[filename]["report"]
        else:
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
            traces.append(self.runOneTx(tx))
        return traces

    def reward(self, traces):
        reward, report, jump_pcs = self.traceAnalyzer.run(self.traces, traces, self.opts["vulnerability"])
        self.traces = traces
        
        return reward, report, jump_pcs

    def loadSeed(self, txList, pcs):
        """
        add arguments of a tx list to seeds
        """
        assert(len(txList) == len(pcs))
        seeds = self.contractAbi.typeHandler.seeds
        visitedPcList = self.contractMap[self.filename]["visited"]
        for i in range(len(txList)):
            if pcs[i].issubset(visitedPcList):
                continue
            self.contractMap[self.filename]["visited"] = visitedPcList.union(pcs[i])
            for arg in txList[i].typedArgs:
                if arg[0] not in seeds:
                    seeds[arg[0]] = [arg[1]]
                else:
                    seeds[arg[0]].append(arg[1])

    def mutate(self, state, action):
        txList = state.txList + []
        actionId = action.actionId
        actionArg = action.actionArg
        if actionId >= 0 and actionId < 2:
            # insert
            if actionArg < 0 or actionArg >= len(self.contractAbi.funcHashList):
                return None
            if len(txList) >= self.maxCallNum:
                return None
            tx = self.contractAbi.generateTx(
                self.contractAbi.funcHashList[actionArg], self.defaultAccount)
            if actionId == 0:
                # insert at first
                txList.insert(0, tx)
            else:
                # insert at last
                txList.append(tx)
        elif actionId < 4:
            # remove
            if len(txList) <= 0:
                # cannot remove
                return None
            if actionId == 2:
                # remove the first
                del txList[0]
            else:
                # remove the last
                txList.pop()
        elif actionId < 7:
            # modify
            if actionArg < 0 or actionArg >= len(txList):
                return None
            funcHash = state.txList[actionArg].hash
            if actionId == 4:
                # modify args
                txList[actionArg].args = self.contractAbi.generateTxArgs(funcHash)
            elif actionId == 5:
                # modify sender
                sender = state.txList[actionArg].sender
                attempt = 100
                while sender == state.txList[actionArg].sender and attempt > 0:
                    randIndex = randint(0, len(self.accounts.keys()) * 2)
                    if randIndex >= len(self.accounts.keys()):
                        sender = self.defaultAccount
                    else:
                        sender = list(self.accounts.keys())[randIndex]
                    attempt -= 1
                txList[actionArg].sender = sender
            else:
                # modify value
                if not self.contractAbi.interface[funcHash]['payable']:
                    # not payable function
                    return None
                value = state.txList[actionArg].value
                attempt = 100
                while value == state.txList[actionArg].value and attempt > 0:
                    value = self.contractAbi.generateTxValue(funcHash)
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
            return
        self.contractAddress = self.evm.deploy(self.contract)

        self.state = State(self.contractAnalysisReport, [])
        self.traces = []
        self.report = []
        # randomFuncIndex = randint(0, len(self.contractAbi.funcHashList)-1)
        # self.state = self.mutate(self.state, actionProcessor.encode(0, randomFuncIndex))
        state, seqLen = self.stateProcessor.encodeState(self.state)
        return state, seqLen

    def random_reset(self, datadir):
        """
        randomly select a contract from datadir and reset
        """
        contract_files = os.listdir(datadir)
        filename = choice(contract_files)
        state, seqLen = self.contract_reset(datadir, filename)
        return state, seqLen, filename

    def contract_reset(self, datadir, filename):
        """
        reset fuzzer with the given contract file
        """
        assert(filename != None)
        full_filename = os.path.join(datadir, filename)
        contract_name = filename.split('.')[0].split("#")[1]
        self.loadContract(full_filename, contract_name)
        return self.reset()

    def step(self, action):
        done = 0
        self.counter += 1
        action = self.actionProcessor.decodeAction(action)
        nextState = self.mutate(self.state, action)
        if not nextState:
            state, seqLen = self.stateProcessor.encodeState(self.state)
            return state, seqLen, 0, done
        # execute transactions
        traces = self.runTxs(nextState.txList)
        # get reward of executions
        reward, report, pcs = self.reward(traces)
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
                reward += 1
                report.append(Exploit(nextState.txList, bal-bal_p))
        # testing
        if self.counter >= FUZZ_CONFIG["max_attempt"] or len(report) > 0:
            done = 1
        # update
        self.state = nextState
        self.traces = traces
        # should exclude repeated reports
        self.report = list(set(self.report + report))
        state, seqLen = self.stateProcessor.encodeState(self.state)
        return state, seqLen, reward, done

    @staticmethod
    def printTxList(txList):
        print("txList:")
        for i in range(len(txList)):
            print("[{}] payload: {}, sender: {}, value: {}".format(
                str(i), txList[i].payload, txList[i].sender, txList[i].value))