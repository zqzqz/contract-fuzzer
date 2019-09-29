from octopus.platforms.ETH.cfg import EthereumCFG

call_op = ["CALL", "CALLCODE", "DELEGATECALL", "SELFDESTRUCT"]

class CFGAnalyzer():
    def __init__(self, filename=None, contract_name=None):
        self.contract_name = None
        self.SS_blocks = {}
        self.CALL_blocks = {}
        self.SS_fun = []
        self.CALL_fun = []
        if filename and contract_name:
            self.load_contract(filename, contract_name)

    def load_contract(self, bin, contract_name):
        if bin and contract_name:
            self.opCFG = EthereumCFG(bin, 'evm', 'dynamic')

    def mark_blocks(self):
        for block in self.opCFG.basicblocks:
            for instr in block.instructions:
                if instr.name == "SSTORE":
                    if block.name in self.SS_blocks:
                        self.SS_blocks[block.name] += 1
                    else:
                        self.SS_blocks[block.name] = 1
                if instr.name in call_op:
                    if block.name in self.CALL_blocks:
                        self.CALL_blocks[block.name] += 1
                    else:
                        self.CALL_blocks[block.name] = 1

    def mark_function(self):
        for f in self.opCFG.functions:
            bbs = []
            for b in f.basicblocks:
                if not (b in bbs):
                    bbs.append(b)
            for b in bbs:
                if b.name in self.SS_blocks:
                    if not (f in self.SS_fun):
                        self.SS_fun.append(f)
                if b.name in self.CALL_blocks:
                    if not (f in self.CALL_fun):
                        self.CALL_fun.append(f)
