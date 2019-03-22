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

    def reset(self):
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


class TimestampOpOracle(Oracle):
    def __init__(self):
        super().__init__("TimestampOp")

    def run_step(self, step):
        if step["op"] == "TIMESTAMP":
            self.results.append(OracleReport(self.name, 1, step["pc"]))


class BlockNumOpOracle(Oracle):
    def __init__(self):
        super().__init__("BlockNumOp")

    def run_step(self, step):
        if step["op"] == "NUMBER":
            self.results.append(OracleReport(self.name, 1, step["pc"]))


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
        super().__init__("EtherTransfer")
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
            gas = hex(2300)

            address = stack[-2]
            input_len = stack[-5]
            if int(input_len, 16) == 0 and address[-40:] in self.accounts and int(gas, 16) == 2300:
                self.results.append(OracleReport(self.name, 1, step["pc"]))


class ExceptionOracle(Oracle):
    def __init__(self):
        super().__init__("Exception")
        self.call_pc = -2

    def run_step(self, step):
        if step["op"] == "CALL":
            self.call_pc = step["pc"]
        if step["pc"] == self.call_pc + 1:
            if int(step["stack"][-1], 16) == 0:
                self.results.append(OracleReport(self.name, 1, self.call_pc))


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
    
    def run_step(self, step):
        if self.call_pc <= 0 and step["op"] == "CALL":
            stack = step["stack"]
            gas = stack[-1]
            address = stack[-2]
            # is it necessary to have value > 0?
            value = stack[-3]

            if int(gas, 16) != 2300 and address[-40:] in self.accounts:
                self.call_pc = step["pc"]
        
        if self.call_pc > 0 and step["op"] == "SSTORE":
            self.results.append(OracleReport(self.name, 1, self.call_pc))
            self.call_pc = -1
