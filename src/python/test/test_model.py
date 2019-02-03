import sys
sys.path.append("..")
from model import *
from interface import Transaction

if __name__ == '__main__':
    actionProcessor = ActionProcessor(3,3)
    stateProcessor = StateProcessor(3,3)
    
    action = Action(1,2)
    action = actionProcessor.encodeAction(action)
    print("action:", action)
    action = actionProcessor.decodeAction(action)
    print("action:", action.actionId, action.actionArg)

    state = State(None, [Transaction("23423424", ["1111", "2222"], "1212", "123123123123")])
    state = stateProcessor.encodeState(state)
    print("state", state)