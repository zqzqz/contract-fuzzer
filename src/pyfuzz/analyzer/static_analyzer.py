from pyfuzz.analyzer.ir_analyzer import Visitor, IrAnalyzer
from pyfuzz.config import ANALYSIS_CONFIG
import logging
import eth_utils
from types import MethodType

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
    def __init__(self, contract):
        self.contract = contract
        self.report = contract.report
        self.encoded_report = contract.encoded_report
        self.func_map = {}
        self.token_size = ANALYSIS_CONFIG["token_size"]
        self.max_dep_num = ANALYSIS_CONFIG["max_dep_num"]
        self.max_line_num = ANALYSIS_CONFIG["max_line_num"]
        self.max_length = ANALYSIS_CONFIG["max_length"]
        for function in contract.functions:
            if function.visibility != "public":
                continue
            full_name = function.full_name
            func_hash = eth_utils.keccak(text=full_name).hex()[:8]
            self.func_map[func_hash] = function.encode_id


class StaticAnalyzer(IrAnalyzer):
    def __init__(self, filename=None, contract_name=None):
        super().__init__(filename, contract_name)
        self.token_size = ANALYSIS_CONFIG["token_size"]
        self.max_dep_num = ANALYSIS_CONFIG["max_dep_num"]
        self.max_line_num = ANALYSIS_CONFIG["max_line_num"]
        self.max_token_value = 2 ** self.token_size
        self.max_length = ANALYSIS_CONFIG["max_length"]
        self.op_map = {"write": 1, "call": 2}
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
        for node in function.nodes:
            if not node.report:
                continue
            for report_line in node.report:
                report_line["func"] = function
                function.report.append(report_line)
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
        # util function, encode zeros when mishitting

        def get_code(var, map):
            if var not in map:
                return 0
            else:
                return map[var]
        # encode state variables from 01...
        count = self.max_token_value // 4
        for state_var in contract.state_variables:
            state_var_map[str(state_var)] = count
            state_var.encode_id = count
            if (count + 1) < self.max_token_value:
                count += 1
        # encode functions from 10...
        count = self.max_token_value * 2 // 4
        for function in contract.functions:
            # init encoded report
            full_name = function.full_name
            func_hash = eth_utils.keccak(text=full_name).hex()[:8]
            encoded_report[func_hash] = []

            arg_map[function.full_name] = {}
            func_map[function.full_name] = count
            # should record the encode_id in objects for the encoding of transactions later
            function.encode_id = count
            if (count + 1) < self.max_token_value:
                count += 1

            # encode arguments
            arg_count = self.max_token_value * 3 // 4
            for arg in function.parameters:
                arg_map[function.full_name][str(arg)] = arg_count
                if (arg_count + 1) < self.max_token_value:
                    arg_count += 1

        # encode each function arguments
        line_count = 0
        for report_line in contract.report:
            if line_count > self.max_line_num:
                break
            full_name = report_line["func"].full_name
            func_hash = eth_utils.keccak(text=full_name).hex()[:8]
            encoded_report[func_hash].append(get_code(full_name, func_map))
            encoded_report[func_hash].append(
                get_code(str(report_line["var"]), state_var_map))
            encoded_report[func_hash].append(
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
                    code = get_code(str(dep), self.solidity_var_map)

                # it is function parameters
                if not code:
                    func = get_code(full_name, arg_map)
                    if func == None:
                        code = 0
                    else:
                        code = get_code(str(dep), func)
                if code:
                    encoded_report[func_hash].append(code)
                    count += 1
            if count < self.max_dep_num:
                encoded_report[func_hash] += [
                    0 for i in range(self.max_dep_num - count)]

        for full_hash in encoded_report:
            if len(encoded_report[func_hash]) < self.max_length:
                encoded_report[func_hash] += [0 for i in range(self.max_length - len(encoded_report[func_hash]))]

        contract.encoded_report=encoded_report
        return encoded_report

    # add property and method to function object
    def pre_taint(self):
        for contract in self.contracts:
            # self means function object
            def setSource(self):
                '''
                :parameter
                :msg.sender; msg.value
                '''
                msg = ['msg.value', 'msg.sender']
                p_vars = [p_var._name for p_var in self._parameters if p_var != None]
                for var in p_vars:
                    self.taintSource.append(var)
                    self.taintList[var] = [var]
                for event in msg:
                    if not (event in self.taintSource):
                        self.taintSource.append(event)
                        self.taintList[event] = [event]

            def setSink(self):
                state_vars = [s_var._name for s_var in self._state_vars_written]
                for var in state_vars: self.taintSink.append(var)
                # anything need to add?

            def setFlag(self):
                for node in self.nodes:
                    if (hex(node._node_type) == '0x50'):
                        node.flag = 0
                    if (hex(node._node_type) in ['0x12', '0x15']):
                        node.flag = 2

            def set_br_taint(self):
                for node in self.nodes:
                    if (hex(node._node_type) in ['0x12', '0x15']):
                        self.branch_taint[node._node_id] = []
                        r_vars = [r_var._name for r_var in node._vars_read if r_var != None]
                        for var_name in r_vars:
                            if var_name in function.taintList:
                                self.branch_taint[node._node_id].append(var_name)

            for function in contract.functions:
                # list of variable, add property 'taintMark' list to each variable
                function.taintSource = []  # taintMark=None
                function.taintSink = []
                function.taintList = {}  # key:mark; value:[v1,v2...]
                function.branch_taint = {}  # key:_node_id; value:[v1,v2..]
                function.current_br_taint = []
                function.setSource = MethodType(setSource, function)
                function.setSink = MethodType(setSink, function)
                function.setFlag = MethodType(setFlag, function)
                function.set_br_taint = MethodType(set_br_taint, function)

    def taint_analysis(self):
        # two important function used in taint analysis
        def propagation(function, stack):
            top = stack[len(stack) - 1]
            # extra policy for branch node
            # IF node
            if (hex(top._node_type) == '0x12'):  # IF
                top.flag -= 1
                function.current_br_taint.append(function.branch_taint[top._node_id])
                return top._sons[1 - top.flag]
            # END_IF node
            elif (hex(top._node_type) == '0x50'):
                while (hex(stack[len(stack) - 1]._node_type) != '0x12'):
                    pop_action(function, stack)
                IF_node = stack[len(stack) - 1]
                function.current_br_taint.pop()
                if (IF_node.flag > 0):
                    return IF_node
                else:
                    pop_action(function, stack)
                    # return top._sons[0]
            # IF_LOOP node
            elif (hex(top._node_type) == '0x15'):
                top.flag -= 1
                function.current_br_taint.append(function.branch_taint[top._node_id])
                return top._sons[top.flag]
            # END_LOOP node
            elif (hex(top._node_type) == '0x52'):
                while (hex(stack[len(stack) - 1]._node_type) != '0x51'):
                    pop_action(function, stack)
                pop_action(function, stack)
                function.current_br_taint.pop()
                # return top._sons[0]
            # straight line flow node
            return top._sons[0]

        def pop_action(function, stack):
            node = stack.pop()
            for var in node._vars_read:
                if var._name in function.taintList:
                    for w_var in node._vars_written:
                        if not (w_var._name in function.taintList[var._name]):
                            function.taintList[var._name].append(w_var._name)
            total_br_taint = []
            for br_taintList in function.current_br_taint:
                total_br_taint.extend(br_taintList)
            for var in node._vars_read:
                if var._name in total_br_taint:
                    for w_var in node._vars_written:
                        if not (w_var._name in function.taintList[var._name]):
                            function.taintList[var._name].append(w_var._name)

        # main part of taint_analysis
        stack = []
        for contract in self.contracts:
            for function in contract.functions:
                # Initialize Source, Sink, taintList of fun;
                function.setSink()
                function.setSource()
                function.setFlag()
                function.set_br_taint()
                if function.nodes == []: break
                # Find the entrance of cfg
                currentNode = function.nodes[0]
                stack.append(currentNode)
                while (currentNode._sons):
                    currentNode = propagation(function, stack)
                    stack.append(currentNode)
                while (stack):
                    pop_action(function, stack)

                    
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
        contract=self.contract
        assert(contract != None)

        report=self._simplify_contract_report(contract)
        if debug:
            print_reports(report)

        encoded_report=self._encode_contract_report(contract)
        if debug:
            print(encoded_report)

        self.report=AnalysisReport(contract)
        return self.report
