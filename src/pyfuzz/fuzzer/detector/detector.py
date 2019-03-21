from pyfuzz.fuzzer.detector.oracle import *


class Vulnerability():
    def __init__(self, vul_type, pc, description=""):
        self.vul_type = vul_type
        self.pc = pc
        self.description = description

    def __eq__(self, other):
        return self.vul_type == other.vul_type and self.pc == other.pc

    def __hash__(self):
        import hashlib
        m = hashlib.md5()
        payload = self.vul_type + str(self.pc)
        m.update(payload.encode("utf-8"))
        return int(m.hexdigest(), 16)

    def __str__(self):
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
        }
        self.oracles = {
            "TimestampOp": TimestampOpOracle(),
            "BlockNumOp": BlockNumOpOracle(),
            "EtherTransfer": EtherTransferOracle(),
            "SendCall": SendCallOracle()
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
        timestamp_op_flag = False
        pc = None
        vulnerabilities = []
        
        for res in self.oracles["TimestampOp"].results:
            if not timestamp_op_flag:
                timestamp_op_flag = True
            if not pc:
                pc = res.pc
        
        if not timestamp_op_flag:
            return vulnerabilities

        send_call_pcs = []
        ether_transfer_pcs = []
        for res in self.oracles["SendCall"].results:
            send_call_pcs.append(res.pc)
        for res in self.oracles["EtherTransfer"].results:
            ether_transfer_pcs.append(res.pc)
        critical_call_pcs = list(set(send_call_pcs).intersection(ether_transfer_pcs))
        if len(critical_call_pcs) > 0:
            vulnerabilities.append(Vulnerability("TimestampDependency", pc))
        return vulnerabilities

    def block_number_dependency_detector(self):
        block_number_op_flag = False
        pc = None
        vulnerabilities = []
        
        for res in self.oracles["BlockNumOp"].results:
            if not block_number_op_flag:
                block_number_op_flag = True
            if not pc:
                pc = res.pc
        
        if not block_number_op_flag:
            return vulnerabilities

        send_call_pcs = []
        ether_transfer_pcs = []
        for res in self.oracles["SendCall"].results:
            send_call_pcs.append(res.pc)
        for res in self.oracles["EtherTransfer"].results:
            ether_transfer_pcs.append(res.pc)
        critical_call_pcs = list(set(send_call_pcs).intersection(ether_transfer_pcs))
        if len(critical_call_pcs) > 0:
            vulnerabilities.append(Vulnerability("BlockNumberDependency", pc))
        return vulnerabilities