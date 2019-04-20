from pyfuzz.analyzer.ir_analyzer import Visitor, IrAnalyzer
from pyfuzz.config import ANALYSIS_CONFIG
import eth_utils
from types import MethodType
import slither
import os


def print_reports(reports):
    if isinstance(reports, list):
        for report in reports:
            print_reports(report)
    elif isinstance(reports, dict):
        for key in list(reports.keys()):
            print("<" + key + ">", end=' ')
            print_reports(reports[key])
        print()
    else:
        print(str(reports), end=' ')


class AnalysisReport():
    def __init__(self, contract):
        self.contract = contract
        self.func_map = {}
        self.token_size = ANALYSIS_CONFIG["token_size"]
        self.max_dep_num = ANALYSIS_CONFIG["max_dep_num"]
        self.max_line_num = ANALYSIS_CONFIG["max_line_num"]
        self.max_length = ANALYSIS_CONFIG["max_length"]
        for function in contract.functions:
            if not (function.visibility in ["public", "external"]):
                continue
            full_name = function.full_name
            func_hash = eth_utils.keccak(text=full_name).hex()[:8]
            self.func_map[func_hash] = function.encode_id

    @property
    def report(self):
        return self.contract.report

    @property
    def encoded_report(self):
        return self.contract.encoded_report


class StaticAnalyzer(IrAnalyzer):
    def __init__(self, filename=None, contract_name=None):
        super().__init__(filename, contract_name)
        self.token_size = ANALYSIS_CONFIG["token_size"]
        self.max_dep_num = ANALYSIS_CONFIG["max_dep_num"]
        self.max_line_num = ANALYSIS_CONFIG["max_line_num"]
        self.max_token_value = 2 ** self.token_size
        self.max_length = ANALYSIS_CONFIG["max_length"]
        self.op_map = {"write": 1, "transfer": 2, "send": 2, "value": 3}
        self.solidity_var_map = {"msg.sender": 1, "msg.value": 2}
        self.report = None

    @staticmethod
    def _parse_node_for_report(node):
        # todo: temporary implementation before taint analysis is avaiable !!
        node.report = []
        for written_var in list(set(node._expression_vars_written)):
            node.report.append({
                "var": written_var,
                "op": "write",
                "deps": node._expression_vars_read
            })
        # todo: how to extract external calls such as transfer and send
        for call in node.external_calls_as_expressions:
            if len(node._expression_vars_read) == 0:
                break
            node.report.append({
                "var": node._expression_vars_read[0],
                "op": "call",
                "deps": node._expression_vars_read
            })
        return node.report

    @staticmethod
    def _parse_function_for_report(function):
        function.report = []
        function.features = {
            "call": len(function._external_calls_as_expressions),
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
        '''
        the key("var") in report is just taintSink or all the variable(sink_taint)
        need to discuss
        '''
        for var in function.taintSink:
            function.report.append({
                "var": var,
                "op": "write",
                "deps": []
            })
            for source in function.taintSource:
                if var in function.taintList[source]:
                    function.report[len(function.report) - 1]["deps"].append(source)

        '''
        add external_calls into report
        here only consider about send and transfer with certain format args
        comments: must include low level calls, which is the critical entry to attacks
        '''
        for ex_call in function._external_calls_as_expressions:
            try:
                op = ex_call.called.member_name
                if op in ["send", "transfer", "value"]:
                    _to = ex_call.called.expression
                    while isinstance(_to, slither.core.expressions.member_access.MemberAccess):
                        _to = _to.expression
                    _to = _to.value  # address, like msg.sender
                    # format like: msg.sender.transfer(payments[msg.sender]);
                    if isinstance(ex_call.arguments[0], slither.core.expressions.index_access.IndexAccess):
                        index_left = ex_call.arguments[0].expression_left.value  # state value
                        index_right = ex_call.arguments[0].expression_right.value  # state value
                        function.report.append({
                            "var": _to,
                            "op": op,
                            "deps": [index_left, index_right]
                        })
                        for var in [index_left, index_right]:
                            for source in function.taintSource:
                                if var in function.taintList[source]:
                                    if not (source in function.report[len(function.report) - 1]["deps"]):
                                        function.report[len(function.report) - 1]["deps"].append(source)
                    else:  # format like: msg.sender.transfer(msg.value)
                        function.report.append({
                            "var": _to,
                            "op": op,
                            "deps": [ex_call.arguments[0].value]
                        })
                        for source in function.taintSource:
                            if ex_call.arguments[0].value in function.taintList[source]:
                                if not (source in function.report[len(function.report) - 1]["deps"]):
                                    function.report[len(function.report) - 1]["deps"].append(source)
            except:
                continue
            else:
                pass
        '''
               Add condition dependance into report
               First transform function.conditionList from {key=mark:value=sink} to {key=sink:value=mark}
               '''
        new_condition_list = {}
        for mark in function.conditionList:
            for var in function.conditionList[mark]:
                if not (var in new_condition_list):
                    new_condition_list[var] = [mark]
                elif not (mark in new_condition_list):
                    new_condition_list[var].append(mark)

        print("show new condition list\n")
        for mark in new_condition_list:
            print('the mark is ', mark._name, ", effect:")
            list = []
            for v in new_condition_list[mark]:
                list.append(v.name)
            print(list)

        for var in new_condition_list:
            function.report.append({
                "var": var,
                "op": "condition",
                "deps": new_condition_list[var]
            })

        for report_line in function.report:
            report_line["func"] = function
        return function.report

    @staticmethod
    def _parse_contract_for_report(contract):
        contract.report = []
        for function in contract.functions:
            if not function.report:
                continue
            contract.report += function.report
        return contract.report

    @staticmethod
    def _simplify_contract_report(contract):
        """
            Only remain state variables, solidity inline variables and function arguments
        """
        state_vars = contract.state_variables
        simplified_report = []
        write_filter = [var.name for var in state_vars] + \
                       ["msg.sender", "msg.value"]
        dep_filter = {}
        for report_line in contract.report:
            function = report_line["func"]
            if function.visibility != "public":
                contract.report.remove(report_line)
                continue
            if function.full_name not in dep_filter:
                func_args = report_line["func"].parameters
                dep_filter[function.full_name] = write_filter
                dep_filter[function.full_name] += [var.name for var in func_args]
            if str(report_line["var"]) not in write_filter:
                contract.report.remove(report_line)
                continue
            for dep in report_line["deps"]:
                if str(dep) not in dep_filter[function.full_name]:
                    report_line["deps"].remove(dep)

        return contract.report

    def _encode_contract_report(self, contract):
        """
            Encode the report to a list of numbers.
            Using configurations in __init__
        """
        encoded_report = {}
        state_var_map = {}
        func_map = {}
        arg_map = {}
        feature_map = {}

        # util function, encode zeros when mishitting

        def get_code(var, map):
            if var not in map:
                return 0
            else:
                return map[var]

        # encode state variables from 0...
        count = 3
        for state_var in contract.state_variables:
            state_var_map[str(state_var)] = count
            state_var.encode_id = count
            if (count + 1) <= self.max_token_value:
                count += 1
        # encode functions from 0...
        count = 1
        for function in contract.functions:
            # init encoded report
            full_name = function.full_name
            func_hash = eth_utils.keccak(text=full_name).hex()[:8]
            encoded_report[func_hash] = {
                "features": [],
                "taint": []
            }
            feature_map[func_hash] = function.features

            arg_map[function.full_name] = {}
            func_map[function.full_name] = count
            # should record the encode_id in objects for the encoding of transactions later
            function.encode_id = count
            if (count + 1) <= self.max_token_value:
                count += 1

            # encode arguments
            arg_count = self.max_token_value - 1
            for arg in function.parameters:
                arg_map[function.full_name][str(arg)] = arg_count
                if (arg_count - 1) >= 1:
                    arg_count -= 1

        # encode each function arguments
        line_count = 0
        for report_line in contract.report:
            if line_count > self.max_line_num:
                break

            full_name = report_line["func"].full_name
            func_hash = eth_utils.keccak(text=full_name).hex()[:8]
            encoded_report[func_hash]["taint"].append(
                get_code(str(report_line["var"]), state_var_map))
            encoded_report[func_hash]["taint"].append(
                get_code(str(report_line["op"]), self.op_map))

            count = 0
            for dep in report_line["deps"]:
                if count > self.max_dep_num:
                    break
                code = 0
                # it is solidity argument
                if not code:
                    code = get_code(str(dep), self.solidity_var_map)

                # it is state variable
                if not code:
                    code = get_code(str(dep), state_var_map)

                # it is function parameters
                if not code:
                    func = get_code(full_name, arg_map)
                    if func == None:
                        code = 0
                    else:
                        code = get_code(str(dep), func)
                if code:
                    encoded_report[func_hash]["taint"].append(code)
                    count += 1
            if count < self.max_dep_num:
                encoded_report[func_hash]["taint"] += [
                    0 for i in range(self.max_dep_num - count)]

        for func_hash in encoded_report:
            if func_hash in feature_map:
                features = feature_map[func_hash]
                encoded_report[func_hash]["features"] = [features["call"], features["msg"], features["block"],
                                                         features["args"], features["payable"]]
            else:
                encoded_report[func_hash]["features"] = [0, 0, 0, 0, 0]
            if len(encoded_report[func_hash]["taint"]) < self.max_length:
                encoded_report[func_hash]["taint"] += [0 for i in
                                                       range(self.max_length - len(encoded_report[func_hash]["taint"]))]
            elif len(encoded_report[func_hash]) > self.max_length:
                encoded_report[func_hash]["taint"] = encoded_report[func_hash]["taint"][:self.max_length]

        contract.encoded_report = encoded_report
        return encoded_report

    # add property and method to function object
    def pre_taint(self):
        '''
        Source and Sink list contains:
        1. function._parameters;
        2. function._solidity_vars_read: like msg.sender, msg.value; in the following url:
                https://github.com/crytic/slither/blob/master/slither/core/declarations/solidity_variables.py
        3. function._state_vars_read/write: like balance[addr]..., they are declared in current contract
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
                function.branch_taint = {}  # key:_node_id; value:[v1,v2..]
                function.current_br_taint = []
                function.setSource = MethodType(setSource, function)
                function.setSink = MethodType(setSink, function)
                function.set_br_taint = MethodType(set_br_taint, function)

                for node in function.nodes:
                    node._taintList = {}  # key:mark; value:[v1,v2...]
                    node._tainted = {}  # key: the vars which has been tainted (except marks); value:mark
                    node._condition = {} # key:var; value:[v1,v2..souce]
                    node._IsParsed = False
                    node._toParse = True

                # Initialize source, sink, taintList and branch_taint of function
                function.setSource()
                function.setSink()
                function.set_br_taint()

    def taint_analysis(self):
        def DFSparse(function, node):

            print("current node is: ", node)
            print('expr of this node: ', node._expression)
            print('type of this node: ', hex(node._node_type))
            dom_expr = [dom._expression for dom in node._fathers]
            print('fathers are:  ')
            for expr in dom_expr: print(expr, ', ', type(expr))
            dom_expr = [dom._expression for dom in node._sons]
            print('sons are:  ')
            for expr in dom_expr: print(expr, ', ', type(expr))

            # Update toParse state of current node
            if (node.fathers):  # nodes besides STARTPOINT
                node._toParse = True
                for father in node.fathers:
                    if not (father._IsParsed):
                        node._toParse = False
                        break

            # stop forward when current node's toParse is false except for IF_LOOP
            if (not (node._toParse) and not (hex(node._node_type) == '0x15')):
                print('stop at node: ', hex(node._node_type), '\n')
                return

            # deal with the case that IF without else
            if node._IsParsed:
                return
            if (node.fathers):
                process(function, node)

            # Update IsParsed state of current node
            node._IsParsed = True
            print('current: ', node, " finish parse\n")
            if (node.sons):
                # deal with for-loop whose sons order is different
                if (hex(node._node_type) == '0x15'):
                    if (hex(node.sons[0]._node_type) == '0x52'):
                        DFSparse(function, node.sons[1])
                        DFSparse(function, node.sons[0])
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
            # filter the taintlist of exitNode and add to function's taintList
            else:
                for mark in node._taintList:
                    for var in node._taintList[mark]:
                        # function.taintList[mark].append(var)
                        if var in function.taintSink:
                            function.taintList[mark].append(var)
            return

        def process(function, node):
            # extra policy for branch nodes or expression nodes
            # TODO : how to deal with if(address.call.value())
            # IF node
            if (hex(node._node_type) == '0x12'):  # IF
                # inherit from a single parent
                copy_taint(node.fathers[0], node)
                # add corresponding br_mark of IF
                function.current_br_taint.append(function.branch_taint[node.node_id])


            # END_IF node
            elif (hex(node._node_type) == '0x50'):
                # inherit from a single parent of parents
                copy_taint(node.fathers[0], node)
                # Combine two father into a single son
                for var in node.fathers[1]._tainted:
                    if not (var in node._tainted):
                        node._tainted[var] = (node.fathers[1]._tainted[var])
                        for mark in node.fathers[1]._tainted[var]:
                            node._taintList[mark].append(var)
                    else:
                        for mark in node.fathers[1]._tainted[var]:
                            if not (mark in node._tainted[var]):
                                node._tainted[var].append(mark)
                                node._taintList[mark].append(var)
                # drop the finished branch taint
                function.current_br_taint.pop()
                return

            # IF_LOOP node
            elif (hex(node._node_type) == '0x15'):
                # inherit from a single parent of two parents
                copy_taint(node.fathers[0], node)
                if not (node._toParse):
                    node._taintList = node.fathers[0]._taintList.copy()
                    node._tainted = node.fathers[0]._tainted.copy()
                    # add corresponding br_mark of IF_LOOP
                    function.current_br_taint.append(function.branch_taint[node.node_id])
                else:
                    pass
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
            br_taint_effect(function, node)

            return

        def copy_taint(from_node, to_node):
            for mark in from_node._taintList:
                to_node._taintList[mark] = from_node._taintList[mark][:]
            for var in from_node._tainted:
                if not (var in to_node._tainted):
                    to_node._tainted[var] = from_node._tainted[var][:]

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

        '''
                Add condition taint information
                '''

        def br_taint_effect(function, node):
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
                if not (var in tmp_2):
                    tmp_2.append(var)

            '''
            deal with var which is tainted by source
            '''
            for var in tmp_2:
                if not (var in node._tainted): continue
                for mark in node._tainted[var]:
                    if not (mark in total_br_taint):
                        total_br_taint.append(mark)

            '''
            deal with source in condition expressions
            '''
            for var in tmp_2:
                if var in node._taintList:
                    if not (var in total_br_taint):
                        total_br_taint.append(var)

            # for var in total_br_taint:
            #     for w_var in node._vars_written:
            #         if not (w_var in node._taintList[var]):
            #             node._taintList[var].append(w_var)
            #             if w_var in node._tainted:
            #                 node._tainted[w_var].append(var)
            #             else:
            #                 node._tainted[w_var] = [var]

            '''
                        Now the total_br_taint is the list of taint sources which effect the condition
                        of current node.
                        Write relations between var_written and condition source
             '''
            for mark in total_br_taint:
                node._condition[mark] = node._vars_written

        # main part of taint_analysis
        for contract in self.contracts:
            print('\ncurrent contract is:  ', contract.name, "\n")
            for function in contract.functions:
                if function.nodes == []: break
                # Find the entrance of cfg
                startNode = function.nodes[0]
                # Parse the dataflow and do taint analysis
                DFSparse(function, startNode)
                # Combine conditions of nodes into conditionList of function
                condition_all_in_one = {}
                for node in function.nodes:
                    for mark in node._condition:
                        if not (mark in condition_all_in_one):
                            condition_all_in_one[mark] = node._condition[mark]
                        else:
                            for var in node._condition[mark]:
                                if not (var in condition_all_in_one[mark]):
                                    condition_all_in_one[mark].append(var)

                # for mark in condition_all_in_one:
                #     print('the mark is ', mark._name, ", effect:")
                #     list = []
                #     for v in condition_all_in_one[mark]:
                #         list.append(v.name)
                #     print(list)

                # Sort by source type and drop duplicate values which have been written into taintList with same key
                para_vars = [p_var for p_var in function._parameters if p_var != None]
                for mark in function._solidity_vars_read:
                    if mark in condition_all_in_one:
                        function.conditionList[mark] = []
                        for var in condition_all_in_one[mark]:
                            if not (var in function.taintList[mark]):
                                function.conditionList[mark].append(var)
                for mark in function._state_vars_read:
                    if mark in condition_all_in_one:
                        function.conditonList[mark] = []
                        for var in condition_all_in_one[mark]:
                            if not (var in function.taintList[mark]):
                                function.conditonList[mark].append(var)
                for mark in para_vars:
                    if mark in condition_all_in_one:
                        function.conditionList[mark] = []
                        for var in condition_all_in_one[mark]:
                            if not (var in function.taintList[mark]):
                                function.conditionList[mark].append(var)

                # for mark in function.conditonList:
                #     print('the mark is ', mark._name, ", effect:")
                #     list = []
                #     for v in function.conditonList[mark]:
                #         list.append(v.name)
                #     print(list)

    def run(self, debug=0):
        """
            return an AnalysisReport object, the report has the format:
            function full name (key) => a list of numbers
        """
        self.pre_taint()
        self.taint_analysis()

        # parse report
        self.parse_contracts(
            Visitor(node_visitor=self._parse_node_for_report))
        self.parse_contracts(
            Visitor(function_visitor=self._parse_function_for_report))
        self.parse_contracts(
            Visitor(contract_visitor=self._parse_contract_for_report))

        # select main contract
        contract = self.contract
        assert (contract != None)

        report = self._simplify_contract_report(contract)
        if debug:
            print_reports(report)

        encoded_report = self._encode_contract_report(contract)
        if debug:
            print(encoded_report)

        self.report = AnalysisReport(contract)
        return self.report


def test():
    filename = os.path.join(os.path.dirname(__file__), '../test/contracts/Test.sol')
    # test DFSparse by Test-parse.sol; test process by Test-taint.sol
    static_analyzer = StaticAnalyzer(filename, "Test")
    static_analyzer.pre_taint()
    static_analyzer.taint_analysis()
    for con in static_analyzer.contracts:
        for fun in con.functions:
            print(fun._name)
            print('source:\n', [var.name for var in fun.taintSource])
            print('sink:\n', [var.name for var in fun.taintSink])
            for var in fun.taintList:
                print('the var is ', var._name, ", taint:")
                list = []
                for v in fun.taintList[var]:
                    list.append(v.name)
                print(list)

            print("Next, show branch taint: \n")
            for i in fun.branch_taint:
                print('node ', i, ' br_taint is ', [var._name for var in fun.branch_taint[i]])
            static_analyzer._parse_function_for_report(fun)


if __name__ == "__main__":
    test()
