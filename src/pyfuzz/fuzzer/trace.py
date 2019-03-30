from pyfuzz.fuzzer.detector.detector import Detector
from pyfuzz.config import FUZZ_CONFIG

branch_op = ["JUMP", "JUMPI", "JUMPDEST", "STOP", "REVERT"]

class TraceAnalyzer:
    def __init__(self):
        self.detector = Detector()

    """
        input:
          ptraces (list(trace)): traces of previous execution
          ctraces (list(trace)): traces of current execution
        return
          report (list(string)): found vulnerabilities
          reward (int): calculated reward
    """
    def run(self, ptraces, ctraces, detect_flag=True):
        report = []
        reward, jumps = self.path_variaty(ptraces, ctraces)
        reward *= FUZZ_CONFIG["path_variaty_reward"]
        if detect_flag:
            report = self.detector.run(ctraces)
            reward += len(report) * FUZZ_CONFIG["vulnerability_reward"]
        return reward, report, jumps

    def path_variaty(self, ptraces, ctraces):
        pJumps = []
        cJumps = []
        ret_jumps = []
        for ptrace in ptraces:
            for state in ptrace:
                if state["op"] in branch_op:
                    pJumps.append(state["pc"])
        for ctrace in ctraces:
            tmp_jumps = []
            for state in ctrace:
                if state["op"] in branch_op:
                    tmp_jumps.append(state["pc"])
                    cJumps.append(state["pc"])
            ret_jumps.append(set(tmp_jumps))

        pJumps = list(set(pJumps))
        cJumps = list(set(cJumps))
        difJumps = list(set(pJumps + cJumps))
        # print(difJumps, pJumps, cJumps)
        if len(difJumps) == 0:
            reward = 0
        else:
            comJumpNum = len(pJumps) + len(cJumps) - len(difJumps)
            reward = (len(pJumps) + len(cJumps) -
                      2 * comJumpNum) / len(difJumps)
        return reward, ret_jumps
