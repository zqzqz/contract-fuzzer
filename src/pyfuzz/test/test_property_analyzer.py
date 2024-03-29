import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))
from pyfuzz.analyzer.static_analyzer import *
import slither
from slither.solc_parsing.declarations.function import FunctionSolc
import logging

class propertyAnalyzer(StaticAnalyzer):
    '''
    Rewrite parse_contracts function to parse deep properties
    '''
    def parse_contracts(self, visitor):
        for contract in self.contracts:
            """
                contract object: https://github.com/trailofbits/slither/blob/master/slither/core/declarations/contract.py
            """
            print('\ncurrent contract is:  ',contract.name,"\n")
            print('funs : ', [fun.name for fun in contract.functions])
            print('modifiers : ',contract.modifiers,[mod.name for mod in contract.modifiers])
            print('modifier inherited: ',contract.modifiers_inherited,[inher_mod.name for inher_mod in contract.modifiers_inherited])
            print('inheritance are: ', [inher.name for inher in contract.inheritance])
            print('immediate_inheritance are: ', [im_inher.name for im_inher in contract.immediate_inheritance])
            print('derived are: ',contract.derived_contracts)
            print('inherited function are: ', [inher_fun.name for inher_fun in contract.functions_inherited])
            print('not inherited function are: ', [inher_fun.name for inher_fun in contract.functions_not_inherited])


            for function in contract.functions:
                """
                    function object: https://github.com/trailofbits/slither/blob/master/slither/core/declarations/function.py
                """
                visitor.function(function)
                # print(type(function))
                print('\ncurrent function is: ',function._name,"\n")
                print(len(function.nodes))
                state_var = []
                state_var.extend(function._state_vars_read)
                state_var.extend(function._state_vars_written)
                print('state vars are: ' ,state_var)
                for var in state_var:
                    print(var._name)
                print('solidity vars read is:\n',function._solidity_vars_read)
                for var in function._solidity_vars_read:
                    print(var._name)
                '''
                self._internal_calls = []
        self._solidity_calls = []
        self._low_level_calls = []
        self._high_level_calls = []
        self._library_calls = []
        self._external_calls_as_expressions = []
                '''
                print("internal call is: ",function._internal_calls)
                if (function._internal_calls):
                    in_call_property = [in_call.name for in_call in function._internal_calls]
                    print(in_call_property)

                print("solidity_calls is: ", function._solidity_calls)
                if (function._solidity_calls):
                    so_call_property = [so_call.name for so_call in function._solidity_calls]
                    print(so_call_property)

                print("low_level_calls is: ", function._low_level_calls)
                if (function._low_level_calls):
                    low_call_property = [low_call.name for low_call in function._low_level_calls]
                    print(low_call_property)

                print("high_level_calls is: ", function._high_level_calls)
                # if (function._high_level_calls):
                #     high_call_property = [high_call.name for high_call in function._high_level_calls]
                #     print(high_call_property)

                print("library_calls is: ", function._library_calls)
                # if (function._library_calls):
                #     lib_call_property = [lib_call.name for lib_call in function._library_calls]
                #     print(lib_call_property)

                print("external_calls_as_expressions is: ", function._external_calls_as_expressions)
                if (function._external_calls_as_expressions):
                    ex_call_property = [ex_call.called.member_name for ex_call in function._external_calls_as_expressions]
                    print(ex_call_property)

                # for ex_call in function._external_calls_as_expressions:
                #     oper_type = ex_call.called.member_name
                #     _to = ex_call.called.expression.value
                #     index_left = ex_call.arguments[0].expressions[0].value # state value
                #     index_right = ex_call.arguments[0].expressions[1].value # state value


                # print("external_calls_as_expressions is: ", function._external_calls_as_expressions[0].called.expression.value)
                # print("external_calls_as_expressions is: ", function._external_calls_as_expressions[0].called.source_mapping)
                # print("external_calls_as_expressions is: ", type(function._external_calls_as_expressions[0].arguments[0])==slither.core.expressions.index_access.IndexAccess)
                # # print("external_calls_as_expressions is: ", function._external_calls_as_expressions[0].arguments[0].value)
                # print("external_calls_as_expressions is: ", type(function._external_calls_as_expressions[0].arguments[0].expressions[1].value))
                #
                #
                # print("called is: ",function.nodes[2].expression.called.source_mapping)
                # print("called is: ",type(function.nodes[2].expression.called))
                # print("call type is: ", function.nodes[2].expression.type_call)
                # print("call type is: ", type(function.nodes[2].expression.type_call))
                # print("call arg is: ", function.nodes[2].expression.arguments[0])
                # print("call arg is: ", type(function.nodes[2].expression.arguments[0]))
                for node in function.nodes:
                    """
                        This node object is for CFG, see https://github.com/trailofbits/slither/blob/master/slither/solc_parsing/cfg
                        and https://github.com/trailofbits/slither/blob/master/slither/core/cfg/node.py
                    """
                    visitor.node(node)
                    # print(type(node))
                    # print('node id is:  ',node._node_id)
                    # print('node.variables read:\n',node.variables_read)
                    # print('############ node begin ###############')
                    # print('expr of this node:  ',node._expression)
                    # print('type of this node:\n',hex(node._node_type))
                    # # print result for cfg analysis
                    # dom_expr = [dom._expression for dom in node._dominators]
                    # print('dominators are:  ')
                    # for expr in dom_expr:print(expr,', ')
                    # dom_expr = [dom._expression for dom in node._sons]
                    # print('sons are:  ')
                    # for expr in dom_expr: print(expr, ', ',type(expr))
                    # if node._sons == [] : print('Over')
                    # for dom in node._sons:
                    #     if dom._expression==None:
                    #         print('find it: ',dom)
                    # dom_expr = [dom._expression for dom in node._fathers]
                    # print('father are:  ')
                    # for expr in dom_expr: print(expr, ', ', type(expr))

                    if node.irs:
                        for ir in node.irs:
                            """
                                ir objects: https://github.com/trailofbits/slither/tree/master/slither/slithir/operations
                            """
                            visitor.ir(ir)
                            # print('###### ir begin ######')
                            # print(type(ir))
                            # print(ir)

def test():
    '''
    this version is to show inheritance and modifier
    '''
    filename = os.path.join(os.path.dirname(__file__), '../test/contracts/BEC.sol')
    property_analyzer = propertyAnalyzer(filename)
    property_analyzer.load_contract(filename, os.listdir('./contracts')[2])
    print('contracts are: ', property_analyzer.contracts)
    visitor = Visitor(None, None, None, None)
    property_analyzer.parse_contracts(visitor)

    # static_analyzer.pre_taint()
    # static_analyzer.taint_analysis()
    # for con in static_analyzer.contracts:
    #     for fun in con.functions:
    #         print(fun._name)
    #         print('source:\n',fun.taintSource)
    #         print('list:\n',fun.taintList)
    #         for var in fun.taintList:
    #             print('the var is ',var._name,", depend on:")
    #             for v in fun.taintList[var]:
    #                 print(v.name,", ")
    #         print('dic:\n',fun.branch_taint)

if __name__ == "__main__":
    test()
