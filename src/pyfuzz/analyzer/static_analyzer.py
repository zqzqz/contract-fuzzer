from pyfuzz.analyzer.ir_analyzer import Visitor, IrAnalyzer
from pyfuzz.config import ANALYSIS_CONFIG
import eth_utils
from types import MethodType
import slither

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
        self.func_map = {}
        self.token_size = ANALYSIS_CONFIG["token_size"]
        self.max_dep_num = ANALYSIS_CONFIG["max_dep_num"]
        self.max_line_num = ANALYSIS_CONFIG["max_line_num"]
        self.max_length = ANALYSIS_CONFIG["max_length"]
        for function in contract.functions:
            if not(function.visibility in ["public","external"]):
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
                    _to = _to.value # address, like msg.sender
                    # format like: msg.sender.transfer(payments[msg.sender]);
                    if isinstance(ex_call.arguments[0], slither.core.expressions.index_access.IndexAccess):
                        index_left = ex_call.arguments[0].expression_left.value  # state value
                        index_right = ex_call.arguments[0].expression_right.value  # state value
                        function.report.append({
                            "var": _to,
                            "op": op,
                            "deps":[index_left,index_right]
                        })
                        for var in [index_left,index_right]:
                            for source in function.taintSource:
                                if var in function.taintList[source]:
                                    if not(source in function.report[len(function.report) - 1]["deps"]):
                                        function.report[len(function.report) - 1]["deps"].append(source)
                    else: # format like: msg.sender.transfer(msg.value)
                        function.report.append({
                            "var": _to,
                            "op": op,
                            "deps":[ex_call.arguments[0].value]
                        })
                        for source in function.taintSource:
                            if ex_call.arguments[0].value in function.taintList[source]:
                                if not (source in function.report[len(function.report) - 1]["deps"]):
                                    function.report[len(function.report) - 1]["deps"].append(source)
            except: continue
            else: pass
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
                encoded_report[func_hash]["features"] = [features["call"], features["msg"], features["block"], features["args"], features["payable"]]
            else:
                encoded_report[func_hash]["features"] = [0, 0, 0, 0, 0]
            if len(encoded_report[func_hash]["taint"]) < self.max_length:
                encoded_report[func_hash]["taint"] += [0 for i in range(self.max_length - len(encoded_report[func_hash]["taint"]))]
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
            self.taintSource.extend(para_vars)
            self.taintSource.extend(self._solidity_vars_read)
            self.taintSource.extend(self._state_vars_read)
            for var in self.taintSource:
                self.taintList[var] = [var]

        def setSink(self):
            self.taintSink.extend(self._state_vars_written)

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
                    r_vars = [r_var for r_var in node._vars_read if r_var != None]
                    for var in r_vars:
                        if var in function.taintList:
                            self.branch_taint[node._node_id].append(var)


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
                nodetypes = [hex(node._node_type) for node in stack]
                IF_node = stack[len(stack) - 1]
                pop_action(function, stack)
                function.current_br_taint.pop()
                nodetypes = [hex(node._node_type) for node in stack]
                if (IF_node.flag > 0):
                    return IF_node
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
            # variables read at current node
            r_vars = [r_var for r_var in node._vars_read if r_var != None]
            for var in r_vars:
                # Make taint mark of taintList
                if var in function.taintList:
                    for w_var in node._vars_written:
                        if not (w_var in function.taintList[var]):
                            function.taintList[var].append(w_var)
                # Make taint mark of branch node_vars
                total_br_taint = []
                for br_taintList in function.current_br_taint:
                    total_br_taint.extend(br_taintList)
                if var in total_br_taint:
                    for w_var in node._vars_written:
                        if not (w_var in function.taintList[var]):
                            function.taintList[var].append(w_var)
        
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
                    # The following three lines can be used to print
                    # nodetypes = [hex(node._node_type) for node in stack]
                    # print('current node is: ',currentNode._expression,'\n','id is: ',currentNode._node_id,' type is : ',hex(currentNode._node_type))
                    # print('stack info: ', nodetypes)
                while (stack):
                    pop_action(function, stack)
                    # To print pop process after traversal of function

                    
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
