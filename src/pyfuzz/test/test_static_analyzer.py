import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))
from pyfuzz.analyzer.static_analyzer import *

def test():
    filename = os.path.join(os.path.dirname(__file__), '../test/contracts/Test-taint.sol')
    analyzer = StaticAnalyzer(filename, "Test")
    report = analyzer.run(debug=1)
    print("function mapping:", report.func_map)
    def function_visitor(function):
        print(function.full_name)
        print('source:',[var.name for var in function.taintSource])
        print('sink:',[var.name for var in function.taintSink])
        print("taint_list", [str(var)+":"+str([str(dep) for dep in function.taintList[var]]) for var in function.taintList])
    analyzer.parse_contracts(Visitor(function_visitor=function_visitor))

def test_taint():
    filename = os.path.join(os.path.dirname(__file__), '../test/contracts/Test-taint.sol')
    # test DFSparse by Test-parse.sol; test process by Test-taint.sol
    static_analyzer = StaticAnalyzer(filename, "Test")
    static_analyzer.pre_taint()
    static_analyzer.taint_analysis()
    for con in static_analyzer.contracts:
        for fun in con.functions:
            print(fun._name)
            print('source:\n',[var.name for var in fun.taintSource])
            print('sink:\n',[var.name for var in fun.taintSink])
            for var in fun.taintList:
                print('the var is ',var._name,", taint:")
                list = []
                for v in fun.taintList[var]:
                    list.append(v.name)
                print(list)

            print("Next, show branch taint: \n")
            for i in fun.branch_taint:
                print('node ',i,' br_taint is ',[var._name for var in fun.branch_taint[i]])

if __name__ == "__main__":
    test()
