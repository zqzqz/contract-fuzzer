from pyfuzz.config import TRAIN_CONFIG

class Action:
    def __init__(self, actionId, actionArg):
        self.actionId = actionId
        self.actionArg = actionArg


class ActionProcessor:

    def __init__(self):
        self.maxFuncNum = TRAIN_CONFIG["max_func_num"]
        self.maxCallNum = TRAIN_CONFIG["max_call_num"]
        self.actionNum = TRAIN_CONFIG["action_num"]

    def encodeAction(self, actionObj):
        actionId = actionObj.actionId
        actionArg = actionObj.actionArg
        assert(actionId >= 0 and actionId < len(actionList))
        assert(actionArg >= 0 and actionArg < self.maxCallNum)
        return actionArg * len(actionList) + actionId

    def decodeAction(self, action):
        assert(action >= 0 and action < self.actionNum)
        return Action(action % len(actionList), action // len(actionList))