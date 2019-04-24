from pyfuzz.fuzzer.detector.oracle import *
from pyfuzz.fuzzer.detector.vulnerability import Vulnerability
from pyfuzz.fuzzer.detector.exploit import Exploit

class Detector():
    def __init__(self, opts={}):
        """
        opts: indicating enabled mode. e.g. { "vulnerability": False }
        """
        self.opts = opts
        if "exploit" not in self.opts:
            self.opts["exploit"] = False
        if "vulnerability" not in self.opts:
            self.opts["vulnerability"] = False
        self.detectors = {}
        self.oracles = {}
        if self.opts["exploit"]:
            self.detectors["CodeInjection"] = self.code_injection_detector
            self.detectors["Selfdestruct"] = self.selfdestruct_detector
            self.oracles["CodeInjection"] = CodeInjectionOracle()
            self.oracles["Selfdestruct"] = SelfdestructOracle()

        if self.opts["vulnerability"]:
            self.detectors["TimestampDependency"] = self.timestamp_dependency_detector
            self.detectors["BlockNumberDependency"] = self.block_number_dependency_detector
            self.detectors["UnhandledException"] = self.unhandled_exception_detector
            self.detectors["Reentrancy"] = self.reentrancy_detector
            self.oracles["TimestampOp"] = TimestampOpOracle()
            self.oracles["BlockNumOp"] = BlockNumOpOracle()
            self.oracles["EtherTransfer"] = EtherTransferOracle()
            self.oracles["SendCall"] = SendCallOracle()
            self.oracles["Exception"] = ExceptionOracle()
            self.oracles["Revert"] = RevertOracle()
            self.oracles["Reentrancy"] = ReentrancyOracle()

    def reset_oracles(self):
        for oracle_num in self.oracles:
            self.oracles[oracle_num].reset()

    def run_oracles(self, trace):
        for step in trace:
            for oracle_name in self.oracles:
                self.oracles[oracle_name].run_step(step)

    def run_one_trace(self, trace):
        vulnerabilities = []
        self.run_oracles(trace)
        for detector_name in self.detectors:
            vulnerabilities += self.detectors[detector_name]()
        return vulnerabilities

    def run(self, traces):
        vulnerabilities = []
        for trace in traces:
            self.reset_oracles()
            vulnerabilities += self.run_one_trace(trace)
        return list(set(vulnerabilities))

    def timestamp_dependency_detector(self):
        vulnerabilities = []
        timestamp_op_flag = self.oracles["TimestampOp"].triggered
        if not timestamp_op_flag:
            return vulnerabilities
        pcs = self.oracles["TimestampOp"].pcs

        # send_call_pcs = self.oracles["SendCall"].pcs
        # ether_transfer_pcs = self.oracles["EtherTransfer"].pcs
        # critical_call_pcs = list(set(send_call_pcs).intersection(ether_transfer_pcs))
        # if len(ether_transfer_pcs) > 0:
        for pc in pcs:
            vulnerabilities.append(Vulnerability("TimestampDependency", pc))
        return vulnerabilities

    def block_number_dependency_detector(self):
        vulnerabilities = []
        block_number_op_flag = self.oracles["BlockNumOp"].triggered
        if not block_number_op_flag:
            return vulnerabilities
        pcs = self.oracles["BlockNumOp"].pcs

        # send_call_pcs = self.oracles["SendCall"].pcs
        # ether_transfer_pcs = self.oracles["EtherTransfer"].pcs
        # critical_call_pcs = list(set(send_call_pcs).intersection(ether_transfer_pcs))
        # if len(ether_transfer_pcs) > 0:
        for pc in pcs:
            vulnerabilities.append(Vulnerability("BlockNumberDependency", pc))
        return vulnerabilities

    def unhandled_exception_detector(self):
        vulnerabilities = []
        revert_flag = self.oracles["Revert"].triggered
        if revert_flag:
            return vulnerabilities
        exception_flag = self.oracles["Exception"].triggered
        if exception_flag:
            for pc in self.oracles["Exception"].pcs:
                vulnerabilities.append(Vulnerability("UnhandledException", pc))
        return vulnerabilities

    def reentrancy_detector(self):
        vulnerabilities = []
        reentrancy_flag = self.oracles["Reentrancy"].triggered
        if reentrancy_flag:
            for pc in self.oracles["Reentrancy"].pcs:
                vulnerabilities.append(Vulnerability("Reentrancy", pc))
        return vulnerabilities

    def code_injection_detector(self):
        vulnerabilities = []
        code_injection_flag = self.oracles["CodeInjection"].triggered
        if code_injection_flag:
            vulnerabilities.append(Exploit("CodeInjection", [None, None, None]))
        return vulnerabilities

    def selfdestruct_detector(self):
        vulnerabilities = []
        selfdestruct_flag = self.oracles["Selfdestruct"].triggered
        if selfdestruct_flag:
            vulnerabilities.append(Exploit("Selfdestruct", [None, None, None]))
        return vulnerabilities