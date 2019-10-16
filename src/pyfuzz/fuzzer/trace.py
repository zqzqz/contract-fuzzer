from pyfuzz.fuzzer.detector.detector import Detector
from pyfuzz.fuzzer.detector.vulnerability import Vulnerability
from pyfuzz.fuzzer.detector.exploit import Exploit
from pyfuzz.config import FUZZ_CONFIG

branch_op = ["JUMP", "JUMPI", "JUMPDEST", "STOP", "REVERT"]
call_op = ["CALL", "CALLCODE", "DELEGATECALL", "SELFDESTRUCT"]

class TraceAnalyzer:
    def __init__(self, opts={}):
        self.detector = Detector(opts)
        self.critical_pc_name = ["CALL", "CALLCODE", "SELFDESTRUCT", "DELEGATECALL", "MLOAD"]

    """
        input:
          ptraces (list(trace)): traces of previous execution
          ctraces (list(trace)): traces of current execution
        return
          report (list(string)): found vulnerabilities
    """
    def run(self, ptraces, ctraces):
        p_pcs = self.get_pcs(ptraces)
        c_pcs = self.get_pcs(ctraces)
        reward = self.path_variaty(p_pcs, c_pcs)
        report = list(set(self.detector.run(ctraces)))
        return reward, report, c_pcs

    def get_seed_candidates(self, ctraces):
        seeds = []
        sha_pc = -1
        pre_state = None
        trace_id = 0
        for trace in ctraces:
            for state in trace:
                if state["op"] == "SHA3" and pre_state and pre_state["op"][:4] == "SWAP":
                    sha_pc = state["pc"]
                elif sha_pc >= 0:
                    try:
                        pass # seeds.append(("bytes", bytearray.fromhex(state["stack"][-1].lstrip("0x"))))
                    except:
                        pass
                    sha_pc = -1
                pre_state = state
            trace_id += 1
        return seeds

    def get_pcs(self, ctraces):
        # TODO
        pcs = []
        for t in ctraces:
            for c in t:
                if c["op"] in self.critical_pc_name:
                    pcs.append(c["pc"])
        return set(pcs)

    def path_variaty(self, p_pcs, c_pcs):
        if len(c_pcs - p_pcs) > 0:
            return 1
        else:
            return 0
