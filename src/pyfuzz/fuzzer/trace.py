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
    def run(self, ptraces, pstate, ctraces, cstate, cfgAnalyzer):
        p_paths = self.parse_trace(ptraces, pstate, cfgAnalyzer.opCFG)
        c_paths = self.parse_trace(ctraces, cstate, cfgAnalyzer.opCFG)
        c_pcs = self.get_pcs(ctraces)
        self.cfgAnalyzer = cfgAnalyzer
        reward = self.cover_metrics(p_paths, c_paths)
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
                        seeds.append(("bytes", bytearray.fromhex(state["stack"][-1].lstrip("0x"))))
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

    def parse_trace(self, ctraces, cstate, opCFG):
        path = {}
        bbs = [block.start_offset for block in opCFG.basicblocks]
        # At the first step of fuzzing, no tx in list
        if cstate==None:
            return None
        '''
        Format of path:
        {funcName:{"trace":[bbs],"SSTOREs":{bb_1:{'SSTORE':2,},...},"CALL":{}}
        '''
        # TODO: whether the trace need to be REVERT when have any calls
        # len(ctraces) = 3 + number of tx with calls; len(txlist) = 3
        for i in range(3):
            funcName = cstate.txList[i].name
            path[funcName] = {}
            path[funcName]["trace"] = []
            path[funcName]["SSTOREs"] = {}
            path[funcName]["CALLs"] = {}
            cbb = 0
            for state in ctraces[i]:
                if state['pc'] in bbs:
                    cbb = state['pc']
                    path[funcName]["trace"].append(cbb)
                if state['op'] in ["SSTORE"]: # Can add other opcodes
                    if not(cbb in path[funcName]["SSTOREs"]):
                        path[funcName]["SSTOREs"][cbb] = {}
                        path[funcName]["SSTOREs"][cbb][state['op']] = 1
                    elif not(state['op'] in path[funcName]["SSTOREs"][cbb]):
                        path[funcName]["SSTOREs"][cbb][state['op']] = 1
                    else:
                        path[funcName]["SSTOREs"][cbb][state['op']] += 1
                    # Also can count directly in cfg
                if state["op"] in call_op:
                    if not(cbb in path[funcName]["CALLs"]):
                        path[funcName]["CALLs"][cbb] = {}
                        path[funcName]["CALLs"][cbb][state['op']] = 1
                    elif not(state['op'] in path[funcName]["CALLs"][cbb]):
                        path[funcName]["CALLs"][cbb][state['op']] = 1
                    else:
                        path[funcName]["CALLs"][cbb][state['op']] += 1
        return path

    def cover_metrics(self,p_paths, c_paths):
        if p_paths == None: return None
        p_funcs = [funcName for funcName in p_paths]
        c_funcs = []
        reward = {}
        '''
        format of reward: {funcName:score,...}
        '''
        for funcName in c_paths:
            c_funcs.append(funcName)
            reward[funcName] = 0
        if not(p_funcs == c_funcs):
            # calculate reward
            for i in range(len(c_funcs)-1, -1, -1):
                if i == len(c_funcs) - 1: # Tx3: we hope it'trace has calls
                    if p_funcs[i] == c_funcs[i]:
                        if p_paths[c_funcs[i]]["trace"] == c_paths[c_funcs[i]]["trace"]:
                            reward[c_funcs] -= 1
                        else:
                            count = 1
                            for bbs in c_paths[c_funcs[i]]["CALLs"]:
                                for call in c_paths[c_funcs[i]]["CALLs"][bbs]:
                                    count += c_paths[c_funcs[i]]["CALLs"][bbs][call]
                            for bbs in p_paths[p_funcs[i]]["CALLs"]:
                                for call in p_paths[p_funcs[i]]["CALLs"][bbs]:
                                    count -= p_paths[p_funcs[i]]["CALLs"][bbs][call]
                            if count < 1: count = 1
                            reward[c_funcs[i]] += count
                    else:
                        count = 0
                        for bbs in c_paths[c_funcs[i]]["CALLs"]:
                            for call in c_paths[c_funcs[i]]["CALLs"][bbs]:
                                count += c_paths[c_funcs[i]]["CALLs"][bbs][call]
                        if count: reward[c_funcs[i]] += 1
                else:pass #TODO
        else:
            for i in range(len(c_funcs)-1, -1, -1):
                if p_paths[c_funcs[i]]["trace"] == c_paths[c_funcs[i]]["trace"]:
                    if i == len(c_funcs) - 1 :
                        reward[c_funcs] -= 1
                    else:
                        pass #TODO
                else:
                    count = 1 # means new blocks finded
                    if i == len(c_funcs) - 1:
                        for bbs in c_paths[c_funcs[i]]["CALLs"]:
                            for call in c_paths[c_funcs[i]]["CALLs"][bbs]:
                                count += c_paths[c_funcs[i]]["CALLs"][bbs][call]
                        for bbs in p_paths[p_funcs[i]]["CALLs"]:
                            for call in p_paths[p_funcs[i]]["CALLs"][bbs]:
                                count -= p_paths[p_funcs[i]]["CALLs"][bbs][call]
                        if count < 1: count = 1
                    else:
                        for bbs in c_paths[c_funcs[i]]["SSTOREs"]:
                            for call in c_paths[c_funcs[i]]["SSTOREs"][bbs]:
                                count += c_paths[c_funcs[i]]["SSTOREs"][bbs][call]
                        for bbs in p_paths[p_funcs[i]]["SSTOREs"]:
                            for call in p_paths[p_funcs[i]]["SSTOREs"][bbs]:
                                count -= p_paths[p_funcs[i]]["SSTOREs"][bbs][call]
                        if count < 1: count = 1
                    reward[c_funcs[i]] += count
        return reward

