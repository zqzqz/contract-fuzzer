from slither.slither import Slither
from slither.slithir.operations import *
import logging


class Visitor():
    def __init__(self, contract_visitor=None, function_visitor=None, node_visitor=None, ir_visitor=None):
        def default_visitor(obj):
            pass
        self.default = default_visitor
        if contract_visitor:
            self.contract = contract_visitor
        else:
            self.contract = default_visitor
        if function_visitor:
            self.function = function_visitor
        else:
            self.function = default_visitor
        if node_visitor:
            self.node = node_visitor
        else:
            self.node = default_visitor
        if ir_visitor:
            self.ir = ir_visitor
        else:
            self.ir = default_visitor


class IrAnalyzer():
    def __init__(self, filename=None, contract_name=None):
        self.slither = None
        self.contract_name = None
        if filename and contract_name:
            self.load_contract(filename, contract_name)

    def load_contract(self, filename, contract_name):
        self.slither = Slither(filename)
        self.contract_name = contract_name

    def parse_contracts(self, visitor):
        for contract in self.contracts:
            """
                contract object: https://github.com/trailofbits/slither/blob/master/slither/core/declarations/contract.py
            """
            visitor.contract(contract)
            for function in contract.functions:
                """
                    function object: https://github.com/trailofbits/slither/blob/master/slither/core/declarations/function.py
                """
                visitor.function(function)
                for node in function.nodes:
                    """
                        This node object is for CFG, see https://github.com/trailofbits/slither/blob/master/slither/solc_parsing/cfg
                        and https://github.com/trailofbits/slither/blob/master/slither/core/cfg/node.py
                    """
                    visitor.node(node)
                    if node.irs:
                        for ir in node.irs:
                            """
                                ir objects: https://github.com/trailofbits/slither/tree/master/slither/slithir/operations
                            """
                            visitor.ir(ir)

    @property
    def contracts(self):
        assert(self.slither != None)
        return self.slither.contracts

    @property
    def contract(self):
        assert(self.slither != None)
        return self.slither.contracts_as_dict()[self.contract_name]
