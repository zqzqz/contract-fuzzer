import logging

# todo

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
        pJumps =[]
        cJumps = []
        for ptrace in ptraces:
            for state in ptrace:
                if state["op"][:4] == "JUMP":
                    pJumps.append(state["pc"])
        for ctrace in ctraces:
            for state in ctrace:
                if state["op"][:4] == "JUMP":
                    cJumps.append(state["pc"])
        difJumps = list(set(pJumps + cJumps))
        comJumpNum = len(pJumps) + len(cJumps) - len(difJumps)
        reward = (len(difJumps) - comJumpNum) / len(difJumps)
        return [], reward