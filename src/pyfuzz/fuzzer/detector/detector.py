from pyfuzz.fuzzer.detector.oracle import *


class Vulnerability():
    def __init__(self, vul_type, pc, description=""):
        self.vul_type = vul_type
        self.pc = pc
        self.description = description

    def __eq__(self, other):
        if self.__class__() != other.__class__():
            return False
        return self.vul_type == other.vul_type and self.pc == other.pc

    def __hash__(self):
        import hashlib
        m = hashlib.md5()
        payload = self.vul_type + str(self.pc)
        m.update(payload.encode("utf-8"))
        return int(m.hexdigest(), 16)

    def __repr__(self):
        return "{}: pc {}".format(self.vul_type, str(self.pc))

    def __dict__(self):
        return {
            "type": self.vul_type,
            "pc": self.pc,
            "description": self.description
        }


class Detector():
    def __init__(self, opts={}):
        """
        opts: indicating enabled detectors. e.g. { "TimestampDependency": False }, default to true
        """
        self.detectors = {
            "TimestampDependency": self.timestamp_dependency_detector,
            "BlockNumberDependency": self.block_number_dependency_detector,
            "UnhandledException": self.unhandled_exception_detector,
            "Reentrancy": self.reentrancy_detector
        }
        self.oracles = {
            "TimestampOp": TimestampOpOracle(),
            "BlockNumOp": BlockNumOpOracle(),
            "EtherTransfer": EtherTransferOracle(),
            "SendCall": SendCallOracle(),
            "Exception": ExceptionOracle(),
            "Revert": RevertOracle(),
            "Reentrancy": ReentrancyOracle()
        }
        for det in opts:
            if det in self.detectors and opts[det] == False:
                self.detectors.pop(det, None)

    def reset_oracles(self):
        for oracle_num in self.oracles:
            self.oracles[oracle_num].reset()

    def run_oracles(self, trace):
        for step in trace:
            for oracle_num in self.oracles:
                self.oracles[oracle_num].run_step(step)

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

        send_call_pcs = self.oracles["SendCall"].pcs
        ether_transfer_pcs = self.oracles["EtherTransfer"].pcs
        critical_call_pcs = list(set(send_call_pcs).intersection(ether_transfer_pcs))
        if len(critical_call_pcs) > 0:
            for pc in pcs:
                vulnerabilities.append(Vulnerability("TimestampDependency", pc))
        return vulnerabilities

    def block_number_dependency_detector(self):
        vulnerabilities = []
        block_number_op_flag = self.oracles["BlockNumOp"].triggered
        if not block_number_op_flag:
            return vulnerabilities
        pcs = self.oracles["BlockNumOp"].pcs

        send_call_pcs = self.oracles["SendCall"].pcs
        ether_transfer_pcs = self.oracles["EtherTransfer"].pcs
        critical_call_pcs = list(set(send_call_pcs).intersection(ether_transfer_pcs))
        if len(critical_call_pcs) > 0:
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