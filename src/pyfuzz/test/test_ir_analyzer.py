import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))
from pyfuzz.analyzer.ir_analyzer import *

def test():
    filename = os.path.join(os.path.dirname(__file__), '../test/contracts/Test.sol')
    ir_analyzer = IrAnalyzer(filename, "Test")
    def node_visitor(node):
        print(str(node))
        if len(node._vars_read) > 0:
            print("\tread:", end=' ')
            for exp in node._vars_read:
                print(str(exp), end=' ')
            print()
        if len(node._vars_written) > 0:
            print("\twrite:", end=' ')
            for exp in node._vars_written:
                print(str(exp), end=' ')
            print()

    def function_visitor(function):
        print(function.full_name, [v.name for v in function.variables_read])
    
    visitor = Visitor(function_visitor=function_visitor, node_visitor=node_visitor)
    # visitor = Visitor()
    ir_analyzer.parse_contracts(visitor)

if __name__ == "__main__":
    test()