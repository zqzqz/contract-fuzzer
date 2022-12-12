from pyfuzz.fuzzer.detector.detector import Detector
from pyfuzz.fuzzer.detector.vulnerability import Vulnerability
from pyfuzz.fuzzer.detector.exploit import Exploit
from pyfuzz.config import FUZZ_CONFIG

branch_op = ["JUMP", "JUMPI", "JUMPDEST", "STOP", "REVERT"]
call_op = ["CALL", "CALLCODE", "DELEGATECALL", "SELFDESTRUCT"]

class TraceAnalyzer:
    def __init__(self, opts={}):
        self.detector = Detector(opts)

    """
        input:
          ptraces (list(trace)): traces of previous execution
          ctraces (list(trace)): traces of current execution
        return
          report (list(string)): found vulnerabilities
          reward (int): calculated reward
    """
    def run(self, ptraces, ctraces):
        reward, jumps, _, paths = self.path_variaty(ptraces, ctraces)
        reward *= FUZZ_CONFIG["path_variaty_reward"]
        seeds = self.get_seed_candidates(ctraces)
        report = list(set(self.detector.run(ctraces)))
        for rep in report:
            if isinstance(rep, Vulnerability):
                reward += FUZZ_CONFIG["vulnerability_reward"]
            elif isinstance(rep, Exploit):
                reward += FUZZ_CONFIG["exploit_reward"]
        return reward, report, jumps, seeds, paths

    def get_seed_candidates(self, ctraces):
        seeds = []
        sha_pc = -1
        pre_state = None
        trace_id = 0
        for trace in ctraces:
            seeds.append([])
            for state in trace:
                if state["op"] == "SHA3" and pre_state and pre_state["op"][:4] == "SWAP":
                    sha_pc = state["pc"]
                elif sha_pc >= 0:
                    try:
                        seeds[trace_id].append(("bytes", bytearray.fromhex(state["stack"][-1].lstrip("0x"))))
                    except:
                        pass
                    sha_pc = -1
                pre_state = state
            trace_id += 1
        return seeds

    def path_variaty(self, ptraces, ctraces):
        pJumps = []
        cJumps = []
        ret_jumps = []
        ret_jumpi = []
        ret_paths = []
        for ptrace in ptraces:
            for state in ptrace:
                if state["op"] in branch_op:
                    pJumps.append(state["pc"])
        for ctrace in ctraces:
            tmp_jumps = []
            tmp_path = ""
            for state in ctrace:
                tmp_path += hex(state["pc"])[2:]
                if state["op"] in branch_op:
                    tmp_jumps.append(state["pc"])
                    cJumps.append(state["pc"])
                    if state["op"] == "JUMPI":
                        ret_jumpi.append(state["pc"])
            ret_jumps.append(set(tmp_jumps))
            ret_paths.append(hash(tmp_path))

        pJumps = list(set(pJumps))
        cJumps = list(set(cJumps))
        difJumps = list(set(pJumps + cJumps))
        ret_jumpi = list(set(ret_jumpi))

        # print(difJumps, pJumps, cJumps)
        if len(difJumps) == 0:
            reward = 0
        else:
            comJumpNum = len(pJumps) + len(cJumps) - len(difJumps)
            reward = (len(pJumps) + len(cJumps) -
                      2 * comJumpNum) / len(difJumps)
        return reward, ret_jumps, ret_jumpi, ret_paths