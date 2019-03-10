import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))
from pyfuzz.trainer.model import *
from pyfuzz.analyzer.static_analyzer import *
from pyfuzz.fuzzer.interface import Transaction

if __name__ == '__main__':
    actionProcessor = ActionProcessor()
    stateProcessor = StateProcessor()
    
    action = Action(1,2)
    action = actionProcessor.encodeAction(action)
    print("action:", action)
    action = actionProcessor.decodeAction(action)
    print("action:", action.actionId, action.actionArg)

    filename = os.path.join(os.path.dirname(__file__), '../../static/test/Test.sol')
    analyzer = StaticAnalyzer(filename, "Test")
    report = analyzer.run(debug=0)

    state = State(report, [Transaction(list(report.func_map.keys())[0], ["1111111111111111111", "2222222222222222222222"], "121212121212121212121212", "123123123123")])
    state, seqLen = stateProcessor.encodeState(state)
    print("state", state)