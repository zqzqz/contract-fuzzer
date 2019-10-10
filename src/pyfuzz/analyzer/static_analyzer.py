from pyfuzz.analyzer.ir_analyzer import Visitor, IrAnalyzer
import eth_utils
from types import MethodType
from slither.core.expressions import *
from slither.solc_parsing.declarations.function import *

def print_reports(reports):
    if isinstance(reports, list):
        for report in reports:
            print_reports(report)
    elif isinstance(reports, dict):
        for key in list(reports.keys()):
            print("<"+key+">", end=' ')
            print_reports(reports[key])
        print()
    else:
        print(str(reports), end=' ')


class AnalysisReport():
    def __init__(self, contract, functionHashes):
        self.contract = contract
        self.func_map = {}
        for function in contract.functions:
            if not(function.visibility in ["public","external"]):
                continue
            # pass in functionHashes because of the difference of function full_name in slither and eth_abi
            if function.name == "fallback":
                self.func_map[""] = function
            else:
                for full_name in functionHashes:
                    if full_name.startswith(function.name + "("):
                        self.func_map[functionHashes[full_name]] = function

    def get_function(self, func_hash):
        if func_hash in self.func_map:
            return self.func_map[func_hash]
        else:
            raise Exception("AnalysisReport.get_function: function not exist in analysis")

    def get_dependency(self, func_hash):
        if func_hash not in self.func_map:
            raise Exception("AnalysisReport.get_dependency: function not exist in analysis")
        else:
            for v in self.func_map[func_hash].taintList:
                if v in res:
                    res[v] = list(set(res[v] + self.func_map[func_hash].taintList[v]))
                else:
                    res[v] = self.func_map[func_hash].taintList[v]
            for v in self.func_map[func_hash].conditionList:
                if v in res:
                    res[v] = list(set(res[v] + self.func_map[func_hash].conditionList[v]))
                else:
                    res[v] = self.func_map[func_hash].conditionList[v]
            return res

    def get_data_dependency(self, func_hash):
        if func_hash not in self.func_map:
            raise Exception("AnalysisReport: function not exist in analysis")
        else:
            return self.func_map[func_hash].taintList

    def get_control_dependency(self, func_hash):
        if func_hash not in self.func_map:
            raise Exception("AnalysisReport: function not exist in analysis")
        else:
            return self.func_map[func_hash].conditionList

    def get_conditions(self, func_hash):
        if func_hash not in self.func_map:
            raise Exception("AnalysisReport: function not exist in analysis")
        else:
            return self.func_map[func_hash].conditions

    def get_feature(self, func_hash):
        if func_hash not in self.func_map:
            if func_hash == "":
                return {
                "call": 0,
                "msg": 0,
                "block": 0,
                "args": 0,
                "payable": 0
                }
            raise Exception("AnalysisReport: function not exist in analysis")
        else:
            return self.func_map[func_hash].features

    def is_function_critical(self, func_hash):
        return self.get_feature(func_hash)["call"] > 0

    def _function_read(self, function):
        result = function._vars_read
        for call in function.internal_calls:
            if isinstance(call, FunctionSolc):
                result.extend(self._function_read(call))
        return list(set(result))

    def _function_written(self, function):
        result = function._vars_written
        for call in function.internal_calls:
            if isinstance(call, FunctionSolc):
                result.extend(self._function_written(call))
        return list(set(result))

class StaticAnalyzer(IrAnalyzer):
    def __init__(self, filename=None, contract_name=None):
        super().__init__(filename, contract_name)
        self.op_map = {"write": 1, "transfer": 2, "send": 2, "value": 3}
        self.solidity_var_map = {"msg.sender": 1, "msg.value": 2}
        self.report = None

    def extract_feature(self):
        for function in self.contract.functions:
            function.features = {
                "call": len(function.external_calls_as_expressions + function.all_internal_calls() + 
                    function.all_low_level_calls() + function.all_high_level_calls()),
                "msg": 0,
                "block": 0,
                "args": len(function.parameters),
                "payable": int(function.payable)
            }
            for v in function.variables_read:
                if v and v.name:
                    if v.name.find("msg.") >= 0:
                        function.features["msg"] += 1
                    elif v.name.find("block.") >= 0:
                        function.features["block"] += 1

    def _simplify_contract_report(self, contract):
        """
            Only remain state variables, solidity inline variables and function arguments
        """
        for function in contract.functions:
            for source in function.taintList:
                if source not in function.taintSource:
                    del function.taintList["source"]
                    continue
                for sink in function.taintList[source]:
                    if sink not in function.taintSink:
                        function.taintList[source].remove(i)
            for source in function.conditionList:
                if source not in function.taintSource:
                    del function.conditionList["source"]
                    continue
                for sink in function.conditionList[source]:
                    if sink not in function.taintSink:
                        function.conditionList[source].remove(sink)

    # add property and method to function object
    def pre_taint(self):
        '''
        Source and Sink list contains:
        1. function._solidity_vars_read: like msg.sender, msg.value; in the following url:
                https://github.com/crytic/slither/blob/master/slither/core/declarations/solidity_variables.py
        2. function._state_vars_read/write: like balance[addr]..., they are declared in current contract
        3. function._parameters;
        form Source list by the order of solidity_vars, state_vars, paras
        '''
        def setSource(self):
            para_vars = [p_var for p_var in self._parameters if p_var != None]
            self.taintSource.extend(self._solidity_vars_read)
            self.taintSource.extend(self._state_vars_read)
            self.taintSource.extend(para_vars)
            for var in self.taintSource:
                self.taintList[var] = []
                for node in self.nodes:
                    node._taintList[var] = []

        def setSink(self):
            self.taintSink.extend(self._state_vars_written)

        def set_br_taint(self):
            for node in self.nodes:
                if (hex(node._node_type) in ['0x12', '0x15']):
                    r_vars = [r_var for r_var in node._vars_read if r_var != None]
                    self.branch_taint[node._node_id] = r_vars

        # main code of pre_taint
        for contract in self.contracts:
            for function in contract.functions:
                '''
                taintList: key<-mark; value<-[v1,v2...]
                branch_taint: key<-_node_id; value<-[v1,v2...]
                current_br_taint: means current propagation for branch, 
                    which consist of branch_taint's value
                '''
                function.taintSource = []  # taintMark=None
                function.taintSink = []
                function.taintList = {}  # key:mark; value:[v1,v2...]
                function.conditionList = {} # key:mark; value:[v1,v2..sink]
                function.branch_taint = {}  # key:_node_id; value:[v1,v2..nodo._vars_read]
                function.conditions = {} # key:_node_id; value:{"cond": [state_vars], "deps": [inputs]}
                function.current_br_taint = []
                function.setSource = MethodType(setSource, function)
                function.setSink = MethodType(setSink, function)
                function.set_br_taint = MethodType(set_br_taint, function)

                for node in function.nodes:
                    node._taintList = {} # key:mark; value:[v1,v2...]
                    node._tainted = {} # key: the vars which has been tainted (except marks); value:mark
                    node._condition = {} # key:var; value:[v1,v2..souce]
                    node._IsParsed = False
                    node._toParse = True

                # Initialize source, sink, taintList and branch_taint of function
                function.setSource()
                function.setSink()
                function.set_br_taint()

    def taint_analysis(self):
        def DFSparse(function, node):

            # Update toParse state of current node
            if (node.fathers): # nodes besides STARTPOINT
                node._toParse = True
                for father in node.fathers:
                    if not(father._IsParsed):
                        node._toParse = False
                        break

            # stop forward when current node's toParse is false except for IF_LOOP
            if (not(node._toParse) and not(hex(node._node_type) == '0x15')):
                return

            # deal with the case that IF without else
            if node._IsParsed:
                return
            if (node.fathers):
                process(function,node)

            # Update IsParsed state of current node
            node._IsParsed = True
            if (node.sons):
                # deal with for-loop whose sons order is different
                if (hex(node._node_type) == '0x15'):
                    if (hex(node.sons[0]._node_type) == '0x52'):
                        DFSparse(function,node.sons[1])
                        DFSparse(function,node.sons[0])
                        return
                # normal sons order
                for son in node.sons:
                    # transfer loop circle into two lines and inherit the loop taints
                    if ((hex(son._node_type) == '0x15') and not (hex(node._node_type) == '0x51')):
                        son._toParse = True
                        son._taintList = node._taintList.copy()
                        son._tainted = node._tainted.copy()
                        return
                    DFSparse(function, son)
            # filter the taintlist of exitNode and add to function's taintList after sorting
            else:
                '''
                Filter the taintlist of exitNode: keep Sink and drop others
                '''
                for mark in node._taintList:
                    for var in node._taintList[mark]:
                        if var in function.taintSink:
                            function.taintList[mark].append(var)
            return

        def process(function,node):
            # extra policy for branch nodes or expression nodes
            # TODO : how to deal with if(address.call.value())
            # IF node
            if (hex(node._node_type) == '0x12'):  # IF
                # inherit from a single parent
                copy_taint(node.fathers[0],node)
                # add corresponding br_mark of IF
                function.current_br_taint.append(function.branch_taint[node.node_id])
                function.conditions[node._node_id] = {
                    "states": [],
                    "consts": [],
                    "deps": []
                }
                return


            # END_IF node
            elif (hex(node._node_type) == '0x50'):
                # inherit from a single parent of parents
                copy_taint(node.fathers[0],node)
                # Combine two father into a single son
                if len(node.fathers) > 1:
                    for var in node.fathers[1]._tainted:
                        if not(var in node._tainted):
                            node._tainted[var] = (node.fathers[1]._tainted[var])
                            for mark in node.fathers[1]._tainted[var]:
                                node._taintList[mark].append(var)
                        else:
                            for mark in node.fathers[1]._tainted[var]:
                                if not(mark in node._tainted[var]):
                                    node._tainted[var].append(mark)
                                    node._taintList[mark].append(var)
                # drop the finished branch taint
                function.current_br_taint.pop()
                return

            # IF_LOOP node
            elif (hex(node._node_type) == '0x15'):
                # inherit from a single parent of two parents
                copy_taint(node.fathers[0], node)
                if not(node._toParse):
                    node._taintList = node.fathers[0]._taintList.copy()
                    node._tainted = node.fathers[0]._tainted.copy()
                    # add corresponding br_mark of IF_LOOP
                    function.current_br_taint.append(function.branch_taint[node.node_id])
                else:pass
                return

            # END_LOOP node
            elif (hex(node._node_type) == '0x52'):
                # inherit from a single parent of two parents
                copy_taint(node.fathers[0], node)
                # drop the finished branch taint
                function.current_br_taint.pop()
                return
            
            # START_LOOP node
            elif (hex(node._node_type) == '0x51'):
                # inherit from a single parent of two parents
                copy_taint(node.fathers[0], node)
                return

            # straight line flow node which has a single parent and a single child
            # inherit from a single parent ( or parent of parents )
            copy_taint(node.fathers[0], node)
            # update taintList and tainted for expression node
            propagation(node)
            br_taint_effect(function,node)

            return

        def copy_taint(from_node,to_node):
            for mark in from_node._taintList:
                to_node._taintList[mark] = from_node._taintList[mark][:]
            for var in from_node._tainted:
                if not(var in to_node._tainted):
                    to_node._tainted[var]=from_node._tainted[var][:]

        def propagation(node):
            r_vars = [r_var for r_var in node._vars_read if r_var != None]
            for var in r_vars:
                if (var in node._taintList):  # var is taint mark
                    for w_var in node._vars_written:
                        if not (w_var in node._taintList[var]):
                            node._taintList[var].append(w_var)
                            if w_var in node._tainted:
                                node._tainted[w_var].append(var)
                            else:
                                node._tainted[w_var] = [var]
                if (var in node._tainted):
                    for w_var in node._vars_written:
                        for mark in node._tainted[var]:  # mark is taint mark
                            if not (w_var in node._taintList[mark]):
                                node._taintList[mark].append(w_var)
                                if w_var in node._tainted:
                                    node._tainted[w_var].append(mark)
                                else:
                                    node._tainted[w_var] = [mark]
            

        def br_taint_effect(function,node):
            total_br_taint = []
            tmp_1 = []
            tmp_2 = []
            '''
            Collect all variables in conditions at this node together into tmp_1
            '''
            for br in function.current_br_taint:
                tmp_1.extend(br)
            '''
            Drop the duplicate variables (tmp_2 contains source, sink and other variables
            '''
            for var in tmp_1:
                if not(var in tmp_2):
                    tmp_2.append(var)
            '''
            deal with var which is tainted by source
            '''
            for var in tmp_2:
                if not(var in node._tainted): continue
                for mark in node._tainted[var]:
                    if not(mark in total_br_taint):
                        total_br_taint.append(mark)
            
            '''
            deal with source in condition expressions
            '''
            
            for var in tmp_2:
                if var in node._taintList:
                    if not(var in total_br_taint):
                        total_br_taint.append(var)

            '''
            Now the total_br_taint is the list of taint sources which effect the condition
            of current node.
            Write relations between var_written and condition source
            '''
            for mark in total_br_taint:
                node._condition[mark] = node._vars_written


        def search_const_in_condition(expression):
            consts = []
            if isinstance(expression, BinaryOperation):
                consts.extend(search_const_in_condition(expression.expression_left))
                consts.extend(search_const_in_condition(expression.expression_right))
            elif isinstance(expression, Literal):
                consts.append(expression.value)
            else:
                pass
            return consts

        # main part of taint_analysis
        for contract in self.contracts:
            for function in contract.functions:
                if function.nodes == []: break
                # Find the entrance of cfg
                startNode = function.nodes[0]
                # Parse the dataflow and do taint analysis
                DFSparse(function,startNode)
                # Combine conditions of nodes into conditionList of function
                para_vars = [p_var for p_var in function._parameters if p_var != None]
                condition_all_in_one = {}
                for node in function.nodes:
                    for mark in node._condition:
                        if not(mark in condition_all_in_one):
                            condition_all_in_one[mark] = node._condition[mark]
                        else:
                            for var in node._condition[mark]:
                                if not(var in condition_all_in_one[mark]):
                                    condition_all_in_one[mark].append(var)

                    #extract condition information
                    if node._node_id in function.conditions:
                        for s in node._state_vars_read:
                            if s not in node._tainted or len(node._tainted[s]) == 0:
                                if s not in function.conditions[node._node_id]["states"]:
                                    function.conditions[node._node_id]["states"].append(s)
                        for v in node._vars_read:
                            if v not in node._tainted:
                                continue
                            for s in node._tainted[v]:
                                if s in para_vars and s not in function.conditions[node._node_id]:
                                    function.conditions[node._node_id]["deps"].append(s)
                        function.conditions[node._node_id]["consts"].extend(search_const_in_condition(node.expression))
                                    
                # Sort by source type and drop duplicate values which have been written into taintList with same key
                for mark in function._solidity_vars_read:
                    if mark in condition_all_in_one:
                        function.conditionList[mark]=[]
                        for var in condition_all_in_one[mark]:
                            if not(var in function.taintList[mark]):
                                function.conditionList[mark].append(var)
                        if not(function.conditionList[mark]):
                            del function.conditionList[mark]                                
                for mark in function._state_vars_read:
                    if mark in condition_all_in_one:
                        function.conditionList[mark]=[]
                        for var in condition_all_in_one[mark]:
                            if not(var in function.taintList[mark]):
                                function.conditionList[mark].append(var)
                        if not(function.conditionList[mark]):
                            del function.conditionList[mark]                                
                for mark in para_vars:
                    if mark in condition_all_in_one:
                        function.conditionList[mark]=[]
                        for var in condition_all_in_one[mark]:
                            if not(var in function.taintList[mark]):
                                function.conditionList[mark].append(var)
                        if not(function.conditionList[mark]):
                            del function.conditionList[mark]
      
    def run(self, functionHashes, debug=0):
        """
            return an AnalysisReport object, the report has the format:
            function full name (key) => a list of numbers
        """
        # select main contract
        contract=self.contract
        assert(contract != None)

        self.extract_feature()
        self.pre_taint()
        self.taint_analysis()

        report=self._simplify_contract_report(contract)
        if debug:
            print_reports(report)

        self.report=AnalysisReport(contract, functionHashes)
        return self.report
