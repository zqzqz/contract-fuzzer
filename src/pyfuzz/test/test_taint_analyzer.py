import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))
from pyfuzz.analyzer.static_analyzer import StaticAnalyzer


def test():
    # filename = os.path.join(os.path.dirname(__file__), '../test/contracts/Test-taint.sol')
    filename = os.path.join(os.path.dirname(__file__), '../../../../tmp/0x8526f3df4ab4093650b7cf734a839580ee29f6de#Private_Fund.sol')
    # test DFSparse by Test-parse.sol; test process by Test-taint.sol
    # static_analyzer = StaticAnalyzer(filename, "Test")
    static_analyzer = StaticAnalyzer(filename, "Private_Fund")
    static_analyzer.run()
    for con in static_analyzer.contracts:
        for fun in con.functions:
            print(fun._name)
            print('source:\n', [var.name for var in fun.taintSource])
            print('sink:\n', [var.name for var in fun.taintSink])
            print("taintList")
            for var in fun.taintList:
                print(var._name,", taint:", end="")
                list = []
                for v in fun.taintList[var]:
                    list.append(v.name)
                print(list)
            print("conditionList")
            for mark in fun.conditionList:
                print(mark._name, ", condition:", end="")
                list = []
                for v in fun.conditionList[mark]:
                    list.append(v.name)
                print(list)
            print("feature")
            for c in fun.all_internal_calls():
                print(c)
            print(fun.features)

if __name__ == "__main__":
    test()
