import json
import logging
import types

class ContractAbi:
    
    def __init__(self, contract=None):
        self.interface = {}
        if contract != None:
            self.loadAbi(contract)

    """
        Input: json object of contract from solc;
        Used properties: functionHashes & interface
    """
    def loadAbi(self, contract):
        self.interface = {}
        solcAbi = json.loads(contract["interface"])
        hashes = contract["functionHashes"]
        
        for abi in solcAbi:
            if abi["type"] == "constructor":
                continue
            name = abi["name"]
            name += '('
            for _input in abi["inputs"]:
                name += _input["type"]
                name += ","
            if name[-1] == ',':
                name = name[:-1]
            name += ')'

            sig = hashes[name]
            if sig != None:
                self.interface[sig] = abi

    """
        Input: 4 Byte function hash
        Output: transaction data (hash + arguments)
    """
    def generateTxArgs(self, hash):
        if self.interface[hash] == None:
            logging.error("Incorrect function hash")
            return None
        payload = []
        inputAbi = self.interface[hash]["inputs"]
        for abi in inputAbi:
            data = generateValueByType(abi["type"], "random")
            payload.append(data)
        return payload

class Transaction:
    def __init__(self, hash, args, value, sender):
        self.hash = hash
        self.args = args
        self.value = value
        self.sender = sender
        self.trace = None

    @property
    def payload(self):
        payload = self.hash
        for arg in self.args:
            payload += arg
        return payload

def test():
    import evm
    import os
    contract = None
    with open(os.path.join(os.getcwd(), '../static/testContract.json'), 'r') as f:
        contract = json.load(f)
    abi = ContractInterface(contract)
    print(abi.interface)

    tx = Transaction("23423424", ["1111", "2222"], 1, "0x123123123")
    print(tx.payload)

if __name__ == "__main__":
    test()