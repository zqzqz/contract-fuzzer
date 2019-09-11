from pyfuzz.config import TRAIN_CONFIG

class State:
    def __init__(self, txList):
        if len(txList) < TRAIN_CONFIG["max_call_num"]:
            txList = [None for i in range(TRAIN_CONFIG["max_call_num"] - len(txList))] + txList
        self.txList = txList


class StateProcessor:

    def __init__(self):
        self.maxFuncNum = TRAIN_CONFIG["max_func_num"]
        self.maxCallNum = TRAIN_CONFIG["max_call_num"]
        self.maxFuncArg = TRAIN_CONFIG["max_func_arg"]
        self.sequence = None
        self.txNum = None
        self.seqLen = TRAIN_CONFIG["max_line_length"]

    def encodeState(self, stateObj):
        pass

    def decodeState(self, state):
        pass