import logging

class TraceAnalyzer:
    def __init__(self):
        pass

    """
        input:
          ptraces (list(trace)): traces of previous execution
          ctraces (list(trace)): traces of current execution
        return
          report (list(string)): found vulnerabilities
          reward (int): calculated reward
    """
    def run(self, ptraces, ctraces):
        report = []
        reward = self.path_variaty(ptraces, ctraces)
        return report, reward

    def path_variaty(self, ptraces, ctraces):
        pJumps = []
        cJumps = []
        for ptrace in ptraces:
            for state in ptrace:
                if state["op"][:4] == "JUMP":
                    pJumps.append(state["pc"])
        for ctrace in ctraces:
            for state in ctrace:
                if state["op"][:4] == "JUMP":
                    cJumps.append(state["pc"])
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
        return reward
