from pyfuzz.config import TRAIN_CONFIG

class State:
    def __init__(self, txList):
        if len(txList) < TRAIN_CONFIG["max_call_num"]:
            txList = [None for i in range(TRAIN_CONFIG["max_call_num"] - len(txList))] + txList
        self.txList = txList