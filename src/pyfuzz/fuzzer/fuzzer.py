from pyfuzz.evm.evm import EvmHandler
from pyfuzz.fuzzer.interface import ContractAbi, Transaction
from pyfuzz.fuzzer.state import State
from pyfuzz.fuzzer.trace import TraceAnalyzer, branch_op
from pyfuzz.fuzzer.generator import InputGenerator
from pyfuzz.analyzer.static_analyzer import StaticAnalyzer, AnalysisReport
from pyfuzz.fuzzer.detector.exploit import Exploit
from pyfuzz.evm_types.types import fillSeeds, TypeHandler
from pyfuzz.config import FUZZ_CONFIG, DIR_CONFIG

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
        self.inputGenerator = None
        # contract cache. Each element is a dict {"name", "contract", "abi", "report", "visited"}
        self.contractMap = {}
        self.contractAddress = None
        # execution results
        self.traces = []
        self.report = []
        # eth accounts
        self.accounts = self.evm.getAccounts()
        self.defaultAccount = list(self.accounts.keys())[0]
        # analyzers
        self.traceAnalyzer = TraceAnalyzer(opts)
        self.staticAnalyzer = StaticAnalyzer()
        # for test
        self.counter = 0
        # eth accounts as seeds of type address
        with open(os.path.join(DIR_CONFIG["seed_dir"], 'address.json'), 'w') as f:
            json.dump(list(self.accounts.keys()), f, indent="\t")

    @property
    def state(self):
        if self.inputGenerator != None:
            return self.inputGenerator.state
        else:
            return None

    def refreshEvm(self):
        self.evm.reset()

    def loadContract(self, filename, contract_name):
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
            # for mutation schedualing
            self.inputGenerator = inputGenerator(self.contractAbi, self.contractAnalysisReport)
            return True
        else:
            try:
                with open(filename, "r",encoding="utf-8") as f:
                    source = f.read()
                self.contract = self.evm.compile(source, contract_name)
                
                # the address is not used
                # test the deployment
                contractAddress = self.evm.deploy(self.contract)
                if not contractAddress:
                    return False
                
                self.contractAbi = ContractAbi(self.contract, list(self.accounts.keys()))
                # run static analysis
                self.staticAnalyzer.load_contract(filename, contract_name)
                self.contractAnalysisReport = self.staticAnalyzer.run()
                # for mutation schedualing
                self.inputGenerator = InputGenerator(self.contractAbi, self.contractAnalysisReport)
                # set cache
                self.contractMap[filename] = {
                    "name": contract_name,
                    "contract": self.contract,
                    "abi": self.contractAbi,
                    "report": self.contractAnalysisReport,
                    "visited": set([])
                }
                return True
            except Exception as e:
                logger.exception("fuzz.loadContract: {}".format(str(e)))
                return False

    def getContract(self, filename):
        if filename not in self.contractMap:
            raise Exception("filename not found")
        return self.contractMap[filename]

    def runOneTx(self, tx, opts={}):
        if self.contract == None:
            logger.exception("Contract have not been loaded.")
            raise Exception("fuzzer error")
        result = self.evm.sendTx(tx.sender, self.contractAddress,
                                str(tx.value), tx.payload, opts)
        if not result:
            raise Exception("no result from sendTx")
        return result["trace"], result["state"]

    def runTxs(self):
        traces = []
        opts = {}
        calls = []
        state = []
        seeds = TypeHandler().seeds

        for i in range(len(self.state.txList)):
            self.inputGenerator.fill(i, seeds)
            tx = self.state.txList[i]
            if not tx:
                calls.append(0)
                traces.append([])
                continue
            
            # if tx has call, revert it later
            feature = self.contractAnalysisReport.get_feature(tx.hash)
            if "call" in feature and feature["call"] > 0:
                calls.append(feature["call"])
            else:
                calls.append(0)
            tx.updateVisited()
            self.contractMap[self.filename]["abi"].updateVisited(tx.hash)

            trace, state = self.runOneTx(tx, opts)
            new_seeds = self.traceAnalyzer.get_seed_candidates([trace])
            for s in new_seeds:
                fillSeeds(s[1], s[0], seeds)
            for i in range(len(tx.typedArgs)):
                fillSeeds(tx.typedArgs[i][1], tx.typedArgs[i][0], seeds)

            if not trace:
                trace = []
            traces.append(trace)
        
        # if there is any call
        if sum(calls) > 0:
            state = []
            seeds = TypeHandler().seeds
            # revert all calls when executing transactions
            opts["revert"] = True
            for i in range(len(self.state.txList)):
                self.inputGenerator.fill(i, seeds)
                tx = self.state.txList[i]
                if not tx:
                    continue
                trace, state = self.runOneTx(tx, opts)
                if trace:
                    traces.append(trace)
        return traces

    def loadSeed(self, txList, pcs, more_seeds=[]):
        """
        add arguments of a tx list to seeds
        """
        # more_seeds unused

        visitedPcList = self.contractMap[self.filename]["visited"]
        j = 0

        if pcs.issubset(visitedPcList):
            return False
        logger.debug("find new path")
        self.contractMap[self.filename]["visited"] = visitedPcList.union(pcs)

        for i in range(len(txList)):
            if txList[i] == None:
                continue
            
            # get Seeds
            seeds = self.contractAbi.seedMap[txList[i].hash]
            
            for i in range(len(txList[i].typedArgs)):
                fillSeeds(txList[i].typedArgs[i][1], txList[i].typedArgs[i][0], seeds[i])
        return True

    def reset(self):
        """
        reset the fuzzer with current contract
        """
        self.counter = 0
        if not self.contract:
            logger.exception("Contract not inintialized in fuzzer.")
            raise Exception("fuzzer error")
        self.contractAddress = self.evm.deploy(self.contract)

        self.traces = []
        self.report = []
        return self.state

    def random_reset(self, datadir):
        """
        randomly select a contract from datadir and reset
        """
        contract_files = os.listdir(datadir)
        filename = choice(contract_files)
        state, seq_len = self.contract_reset(datadir, filename)
        while seq_len == None:
            try:
                filename = choice(contract_files)
                state = self.contract_reset(datadir, filename)
            except:
                state = None, None
        return state, filename

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
            raise Exception("fuzzer error")

    def step(self):
        done = 0
        self.counter += 1
        reward = 0
        timeout = 0
        try:
            # testing
            if self.counter >= FUZZ_CONFIG["max_attempt"]:
                timeout = 1
            self.inputGenerator.generate()
            # execute transactions
            traces = self.runTxs()
            # get reports of executions
            reward, report, pcs = self.traceAnalyzer.run(self.traces, traces)
            self.traces = traces
            # update seeds
            if self.loadSeed(self.state.txList, pcs, []):
                logger.debug("new path discovered")
            # check whether exploitation happens
            if self.opts["exploit"]:
                self.accounts = self.evm.getAccounts()
                # balance increase
                bal_p = 0
                bal = 0
                for acc in self.accounts.keys():
                    bal_p += int(str(FUZZ_CONFIG["account_balance"]), 16)
                    bal += int(str(self.accounts[acc]), 16)

                if bal > bal_p:
                    report.append(Exploit("BalanceIncrement", self.state.txList))
            # fill in transasactions for exploitation
            for rep in report:
                if isinstance(rep, Exploit):
                    rep.txList = self.state.txList
            # testing
            if len(report) > 0:
                done = 1
            # update
            self.traces = traces
            # should exclude repeated reports
            self.report = list(set(self.report + report))
            self.inputGenerator.feedback(reward)
            return self.state, done, timeout
        except Exception as e:
            import traceback
            logger.error("fuzzer.step: {} {}".format(str(e), traceback.format_exc()))
            return self.state, 0, 1

    def coverage(self):
        # disabled
        return 0

    def printTxList(self):
        print("TX LIST:")
        txList = self.state.txList
        for i in range(len(txList)):
            if not txList[i]:
                continue
            function = ""
            abi = self.contractAbi.interface[txList[i].hash]
            if "name" in abi:
                function = abi["name"]
            print("[{}] function: {}, args: {}, sender: {}, value: {}".format(
                str(i), function, txList[i].args, txList[i].sender[:4], txList[i].value))
