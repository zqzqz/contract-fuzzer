
class Oracle():
    def __init__(self, name=""):
        self.name = name

    @abstractmethod
    def run(self, trace):
        return 0

class TimestampOpOracle(Oracle):
    def __init__(self):
        super().__init__("TimestampOp")
    
    def run(self, trace):