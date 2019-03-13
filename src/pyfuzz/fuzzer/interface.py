import json
import logging
import eth_abi
from pyfuzz.evm_types.types import TypeHandler
from pyfuzz.config import FUZZ_CONFIG


class Transaction:
    def __init__(self, hash, args, value, sender, abi):
        self.hash = hash
        self.args = args
        self.value = value
        self.sender = sender
        self.trace = None
        self.abi = abi

    @property
    def payload(self):
        abi_array = [abi_input["type"] for abi_input in self.abi["inputs"]]
        payload = self.hash + eth_abi.encode_abi(abi_array, self.args).hex()
        return payload


class ContractAbi:

    def __init__(self, contract=None):
        self.interface = {}
        self.funcHashList = []
        self.functionHashes = None
        self.typeHandler = TypeHandler()
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
        self.functionHashes = hashes

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
                self.funcHashList.append(sig)

    def generateTxArgs(self, hash):
        assert(self.interface[hash] != None)
        args = []
        inputAbi = self.interface[hash]["inputs"]
        for abi in inputAbi:
            data = self.typeHandler.fuzzByType(abi["type"], SEED_CONFIG["seed_prob"])
            args.append(data)
        return args

    def generateTxValue(self, hash):
        assert(self.interface[hash] != None)
        inputAbi = self.interface[hash]["inputs"]
        value = ""
        if self.interface[hash]['payable']:
            value = self.typeHandler.fuzzByType("payment", SEED_CONFIG["seed_prob"])
        return value

    """
        Input: function hash
        Output: transaction
    """

    def generateTx(self, hash, sender):
        args = self.generateTxArgs(hash)
        value = self.generateTxValue(hash)
        return Transaction(hash, args, value, sender, self.interface[hash])
