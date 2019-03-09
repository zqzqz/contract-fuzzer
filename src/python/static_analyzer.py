from ir_analyzer import Visitor, IrAnalyzer
import logging


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


class StaticAnalyzer(IrAnalyzer):
    def __init__(self, filename=None, contract_name=None):
        super().__init__(filename, contract_name)
        self.max_token_value = 256
        self.max_read_num = 5
        self.op_map = {"write": 1, "call": 2}
        self.solidity_var_map = {"msg.sender": 1, "msg.value": 2}

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
        write_filter = [var.name for var in state_vars] + ["msg.sender", "msg.value"]
        dep_filter = {}
        for report_line in contract.report:
            function = report_line["func"]
            if function.visibility != "public":
                contract.report.remove(report_line)
                continue
            if function.name not in dep_filter:
                func_args = report_line["func"].parameters
                dep_filter[function.name] = write_filter
                dep_filter[function.name] += [var.name for var in func_args]
            if str(report_line["var"]) not in write_filter:
                contract.report.remove(report_line)
                continue
            for dep in report_line["deps"]:
                if str(dep) not in dep_filter[function.name]:
                    report_line["deps"].remove(dep)

        return contract.report

    def _encode_contract_report(self, contract):
        """
            Encode the report to a list of numbers.
            Using configurations in __init__
        """
        encoded_report = []
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
            arg_map[str(function)] = {}
            func_map[str(function)] = count
            # should record the encode_id in objects for the encoding of transactions later
            function.encode_id = count
            if (count + 1) < self.max_token_value:
                count += 1

            # encode arguments
            arg_count = self.max_token_value * 3 // 4
            for arg in function.parameters:
                arg_map[str(function)][str(arg)] = arg_count
                if (arg_count + 1) < self.max_token_value:
                    arg_count += 1

        # encode each function arguments
        for report_line in contract.report:
            encoded_report.append(get_code(str(report_line["func"]), func_map))
            encoded_report.append(
                get_code(str(report_line["var"]), state_var_map))
            encoded_report.append(
                get_code(str(report_line["op"]), self.op_map))
            count = 0
            for dep in report_line["deps"]:
                if count > self.max_read_num:
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
                    func = get_code(str(report_line["func"]), arg_map)
                    if func == None:
                        code = 0
                    else:
                        code = get_code(str(dep), func)
                if code:
                    encoded_report.append(code)
                    count += 1
            if count < self.max_read_num:
                encoded_report += [0 for i in range(self.max_read_num - count)]
        contract.encoded_report = encoded_report
        return encoded_report

    # todo
    def taint_analysis(self):
        pass

    def run(self, debug=0):
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
        assert(contract != None)

        report = self._simplify_contract_report(contract)
        if debug:
            print_reports(report)
        
        encoded_report = self._encode_contract_report(contract)
        return encoded_report
