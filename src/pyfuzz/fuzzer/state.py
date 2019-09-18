from pyfuzz.config import FUZZ_CONFIG

class State:
    def __init__(self, txList):
        if len(txList) < FUZZ_CONFIG["max_call_num"]:
            txList = [None for i in range(FUZZ_CONFIG["max_call_num"] - len(txList))] + txList
        self.txList = txList