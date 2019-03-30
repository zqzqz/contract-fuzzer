import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))
from pyfuzz.analyzer.static_analyzer import *

def test():
    filename = os.path.join(os.path.dirname(__file__), '../test/contracts/Test.sol')
    analyzer = StaticAnalyzer(filename, "Test")
    report = analyzer.run(debug=1)
    print("function mapping:", report.func_map)
    def function_visitor(function):
        print(function.full_name, end='')
        print([str(t) for t in function.taintList])
    analyzer.parse_contracts(Visitor(function_visitor=function_visitor))

if __name__ == "__main__":
    test()
