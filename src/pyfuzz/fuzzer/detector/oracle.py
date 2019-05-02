from pyfuzz.config import DIR_CONFIG
from abc import abstractmethod
import os
import json


class OracleReport():
    def __init__(self, name, status, pc, description=""):
        self.name = name
        self.status = status
        self.pc = pc
        self.description = description

    def __str__(self):
        return "{}: status {} pc {}".format(self.name, self.status, str(self.pc))

    def __dict__():
        return {
            "name": self.name,
            "status": self.status,
            "pc": self.pc,
            "description": self.description
        }


class Oracle():
    def __init__(self, name=""):
        self.name = name
        self.results = []

    @property
    def triggered(self):
        return len(self.results) > 0

    @property
    def pcs(self):
        return [res.pc for res in self.results]

    @abstractmethod
    def run_step(self, step):
        pass

    def reset(self):
        self.results = []


class TimestampOpOracle(Oracle):
    def __init__(self):
        super().__init__("TimestampOp")
        self.res_stat = 0
        self.res_pcs = []

    def run_step(self, step):
        if step["op"] == "TIMESTAMP":
            if self.res_stat == 0:
                self.res_stat += 1
            self.res_pcs.append(step["pc"])
        if step["op"] in ["CALL"] and len(step["stack"]) >= 3 and int(step["stack"][-3], 16) > 0:
            if self.res_stat == 1:
                self.res_stat = 0
                for pc in self.res_pcs:
                    self.results.append(OracleReport(self.name, 1, pc))
                self.res_pcs = []

    def reset(self):
        super().reset()
        self.res_stat = 0
        self.res_pcs = []

class BlockNumOpOracle(Oracle):
    def __init__(self):
        super().__init__("BlockNumOp")
        self.res_stat = 0
        self.res_pcs = []

    def run_step(self, step):
        if step["op"] == "NUMBER":
            if self.res_stat == 0:
                self.res_stat += 1
            self.res_pcs.append(step["pc"])
        if step["op"] in ["CALL"] and len(step["stack"]) >= 3 and int(step["stack"][-3], 16) > 0:
            if self.res_stat == 1:
                self.res_stat = 0
                for pc in self.res_pcs:
                    self.results.append(OracleReport(self.name, 1, pc))
                self.res_pcs = []

    def reset(self):
        super().reset()
        self.res_stat = 0
        self.res_pcs = []


class EtherTransferOracle(Oracle):
    def __init__(self):
        super().__init__("EtherTransfer")

    def run_step(self, step):
        if step["op"] == "CALL":
            stack = step["stack"]
            if len(stack) < 7:
                return
            value = stack[-3]
            if int(value, 16) > 0:
                self.results.append(OracleReport(self.name, 1, step["pc"]))


class SendCallOracle(Oracle):
    def __init__(self):
        super().__init__("SendCall")
        self.accounts = []
        seed_dir = DIR_CONFIG["seed_dir"]
        json_file = os.path.join(seed_dir, "address.json")
        if os.path.isfile(json_file):
            with open(json_file, "r") as f:
                self.accounts = list(json.load(f))

    def run_step(self, step):
        if step["op"] == "CALL":
            stack = step["stack"]
            if len(stack) < 7:
                return
            gas = stack[-1]
            # todo: vm does not show 2300 gas when calling send
            # gas = hex(2300)

            address = stack[-2]
            input_len = stack[-5]
            if int(input_len, 16) == 0 and address[-40:] in self.accounts and (int(gas, 16) == 0 or int(gas, 16) == 2300):
                self.results.append(OracleReport(self.name, 1, step["pc"]))


class ExceptionOracle(Oracle):
    def __init__(self):
        super().__init__("Exception")
        self.call_pc = -1

    def run_step(self, step):
        if step["op"] == "CALL":
            self.call_pc = step["pc"]
        elif self.call_pc >= 0:
            if len(step["stack"]) > 0 and int(step["stack"][-1], 16) == 0:
                self.results.append(OracleReport(self.name, 1, self.call_pc))
            self.call_pc = -1

    def reset(self):
        super().reset()
        self.call_pc = -1


class RevertOracle(Oracle):
    def __init__(self):
        super().__init__("Revert")

    def run_step(self, step):
        if step["op"] == "REVERT":
            self.results.append(OracleReport(self.name, 1, step["pc"]))


class ReentrancyOracle(Oracle):
    def __init__(self):
        super().__init__("Reentrancy")
        self.accounts = []
        seed_dir = DIR_CONFIG["seed_dir"]
        json_file = os.path.join(seed_dir, "address.json")
        if os.path.isfile(json_file):
            with open(json_file, "r") as f:
                self.accounts = list(json.load(f))
        self.call_pc = -1
        self.write_op_list = ["SSTORE", "CALL", "DELEGATECALL", "CALLCODE"]
    
    def run_step(self, step):
        if self.call_pc < 0 and step["op"] == "CALL":
            stack = step["stack"]
            gas = stack[-1]
            address = stack[-2]
            # is it necessary to have value > 0?
            value = stack[-3]

            if int(gas, 16) != 0 and int(gas, 16) != 2300 and address[-40:] in self.accounts:
                self.call_pc = step["pc"]
        
        elif self.call_pc > 0 and step["op"] in self.write_op_list:
            self.results.append(OracleReport(self.name, 1, self.call_pc))
            self.call_pc = -1

    def reset(self):
        super().reset()
        self.call_pc = -1

class CodeInjectionOracle(Oracle):
    def __init__(self):
        super().__init__("CodeInjection")
        self.accounts = []
        seed_dir = DIR_CONFIG["seed_dir"]
        json_file = os.path.join(seed_dir, "address.json")
        if os.path.isfile(json_file):
            with open(json_file, "r") as f:
                self.accounts = list(json.load(f))
        
    def run_step(self, step):
        if step["op"] == "CALLCODE" or step["op"] == "DELEGATECALL":
            stack = step["stack"]
            address = stack[-2]
            if address[-40:] in self.accounts:
                self.results.append(OracleReport(self.name, 1, step["pc"]))

class SelfdestructOracle(Oracle):
    def __init__(self):
        super().__init__("Selfdestruct")

    def run_step(self, step):
        if step["op"] == "SELFDESTRUCT":
            self.results.append(OracleReport(self.name, 1, step["pc"]))              