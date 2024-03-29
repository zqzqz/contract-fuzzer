import json
import eth_abi
from pyfuzz.evm_types.types import TypeHandler
from pyfuzz.config import FUZZ_CONFIG


class Transaction:
    def __init__(self, hash, args, value, sender, abi, total_visited=0, tmp_visited=0):
        self.hash = hash
        self.args = args
        self.value = value
        self.sender = sender
        self.abi = abi
        self.tmp_visited = tmp_visited
        self.total_visited = total_visited

    @property
    def payload(self):
        abi_array = self.inputTypes
        payload = self.hash + eth_abi.encode_abi(abi_array, self.args).hex()
        return payload

    @property
    def typedArgs(self):
        abi_array = self.inputTypes
        assert(len(abi_array) == len(self.args))
        return [(abi_array[i], self.args[i]) for i in range(len(abi_array))]

    @property
    def inputTypes(self):
        return [abi_input["type"] for abi_input in self.abi["inputs"]]

    def __repr__(self):
        return "payload: {}, sender: {}, value: {}".format(self.payload, self.sender, self.value)

    def __eq__(self, other):
        return self.__class__ == self.__class__ and self.__repr__() == self.__repr__()

    def updateVisited(self):
        self.tmp_visited += 1
        self.total_visited += 1


class ContractAbi:

    def __init__(self, contract=None):
        self.interface = {}
        self.funcHashList = []
        self.functionHashes = None
        self.typeHandlers = {}
        self.visited = {}
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
            if abi["type"] == "fallback":
                abi["inputs"] = []
                self.interface[""] = abi
                self.visited[""] = 0
                self.funcHashList.append("")
                continue
            if abi["type"] != "function":
                continue
            if abi["stateMutability"]=="view":
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
                self.visited[sig] = 0
                self.typeHandlers[sig] = TypeHandler()
                self.funcHashList.append(sig)

    def getSeeds(self, hashList):
        res = TypeHandler().seeds
        try:
            for sig in hasList:
                if sig not in self.typeHandlers:
                    continue
                for _type in self.typeHandlers[sig]:
                    if _type not in res:
                        continue
                    res[_type] = list(set(res[_type] + self.typeHandlers[sig][_type]))
            return res
        except:
            return res

    def generateTxArgs(self, hash, seeds=None):
        assert(self.interface[hash] != None)
        args = []
        inputAbi = self.interface[hash]["inputs"]
        for abi in inputAbi:
            data = self.typeHandlers[hash].fuzzByType(abi["type"], FUZZ_CONFIG["seed_prob"], seeds)
            args.append(data)
        return args

    def generateTxValue(self, hash, seeds=None):
        assert(self.interface[hash] != None)
        inputAbi = self.interface[hash]["inputs"]
        value = 0
        if self.interface[hash]['payable']:
            value = self.typeHandlers[hash].fuzzByType("payment", FUZZ_CONFIG["seed_prob"], seeds)
        return value

    """
        Input: function hash
        Output: transaction
    """
    def generateTx(self, hash, sender, seeds=None):
        args = self.generateTxArgs(hash, seeds)
        if self.interface[hash]['payable']:
            value = self.generateTxValue(hash, seeds)
        else:
            value = 0
        return Transaction(hash, args, value, sender, self.interface[hash], self.visited[hash])

    def updateVisited(self, funcHash):
        try:
            self.visited[funcHash] += 1
        except:
            pass

    def resetVisited(self):
        for funcHash in self.interface:
            self.visited[funcHash] = 0

