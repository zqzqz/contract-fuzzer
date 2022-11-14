from pyfuzz.fuzzer.interface import ContractAbi, Transaction
from pyfuzz.config import CONCOLIC_CONFIG
from mythril.concolic import concolic_execution
from mythril.mythril import MythrilDisassembler
from mythril.concolic.concrete_data import ConcreteData, AccountData, InitialState, TransactionData
from mythril.solidity.soliditycontract import SolidityContract
import eth_abi, random


class MythrilConcolic():

    def __init__ (self, contract_code, contract_abi):
        print(contract_code)
        self.contract_addr = "0xaffeaffeaffeaffeaffeaffeaffeaffeaffeaffe"
        self.attacker_addr = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        self.attacker_account = AccountData({
            "balance": "0xffffffffffffffffffffffffffffffff",
            "code": "",
            "nonce": 0,
            "storage": {}
        })
        self.contract_account = AccountData({
            "balance": "0xffffffffffffffffffffffffffffffff",
            "code": "0x" + contract_code,
            "nonce": 0,
            "storage": {}
        })
        self.init_state = InitialState({
            "accounts": {
                self.attacker_addr: self.attacker_account,
                self.contract_addr: self.contract_account
            }
        })
        print(contract_abi.funcHashList)
        self.contract_abi = contract_abi
        self.useless_jumpi = [i for i in range(0, 16)]
        self.exec_prob = {}
        self.last_it = {}
        self.it = 0
        for i in range (16, len(contract_code)//2):
            if contract_code[2*i:2*i+2] == "57":
                useless = False
                for funcHash in contract_abi.funcHashList:
                    # print (funcHash, contract_code[2*i-32:2*i])
                    if len(funcHash) == 8 and funcHash in contract_code[2*i-32:2*i]:
                        useless = True
                if useless or "348015" in contract_code[2*i-16:2*i]:
                    self.useless_jumpi.append(i)
        print(self.useless_jumpi)

    def run(self, txs, jump_addrs):
        valid_jump_addrs = []
        for jump_addr in jump_addrs:
            if jump_addr in self.useless_jumpi:
                continue
            if jump_addr in self.last_it.keys() and self.it-self.last_it[jump_addr] < CONCOLIC_CONFIG["jump_addr_cooldown"]:
                continue
            valid_jump_addrs.append(jump_addr)
            if jump_addr not in self.exec_prob.keys():
                self.exec_prob[jump_addr] = 1.0
        valid_jump_addrs = sorted(valid_jump_addrs, key=lambda x: (self.exec_prob[x], random.randint(0, 10)), reverse=True)
        print(valid_jump_addrs)
        print(self.exec_prob)
        for jump_addr in valid_jump_addrs:
            result = self.branch_flip(txs, jump_addr)
            print(jump_addr, result)
            if len(result) > 0:
                self.exec_prob[jump_addr] *= CONCOLIC_CONFIG["success_flip_penalty"]
                self.last_it[jump_addr] = self.it
                self.it+=1
                return result
            self.exec_prob[jump_addr] *= CONCOLIC_CONFIG["failed_flip_penalty"]
        return []

    def branch_flip (self, txs, jump_addr):
        steps = []
        for tx in txs:
            if not tx:
                continue
            tmp_trans = TransactionData({
                "address": self.contract_addr,
                "origin": self.attacker_addr,
                "input": "0x" + tx.payload,
                "value": hex(tx.value)
            })
            steps.append(tmp_trans)
        data = ConcreteData({
            "initialState": self.init_state,
            "steps": steps
        })
        print(data)
        result_steps = []
        # print("data created")
        try:
            result = concolic_execution(data, [str(jump_addr)], 5000000)
            if len(result) > 0:
                result_steps = result[0]["steps"]
        except Exception as e:
            print(str(e))
            return []

        default_account = ""
        for tx in txs:
            if tx:
                default_account= tx.sender
                break

        new_txs = []
        for tx in result_steps:
            # print(tx)
            try:
                func_hash = tx["input"][2:10]
                abi = self.contract_abi.interface[func_hash]
                input_types = [abi_input["type"] for abi_input in abi["inputs"]]
                # print(tx["input"][10:])
                args_raw = tx["input"][10:]
                # print(args_raw)
                while len(args_raw) < 1000 or len(args_raw)%64 != 0:
                    args_raw += '0'

                # print(args_raw)
                args = eth_abi.decode_abi(input_types, bytes.fromhex(args_raw))
                print(args)
                # args = eth_abi.decode_abi(input_types, tx["input"][10:].encode("ascii"))
                value = int(tx["value"], base=16)
                sender = default_account
                new_txs.append(Transaction(func_hash, args, value, sender, abi))
            except Exception as e:
                print(str(e))
                #pass

        return new_txs