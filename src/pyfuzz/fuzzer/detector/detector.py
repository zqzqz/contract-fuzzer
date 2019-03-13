# parent class: detector


class vulnerability:
    def __init__(self, vul_type, pc, description={}):
        self.vul_type = vul_type
        self.pc = pc
        self.description = description

    def __eq__(self, other):
        return self.vul_type == other.vul_type and self.pc == other.pc

class Detector():
    def __init__(self):
        pass