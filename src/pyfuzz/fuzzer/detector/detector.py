from pyfuzz.fuzzer.detector.oracle import Oracle

class Vulnerability():
    def __init__(self, vul_type, pc, description={}):
        self.vul_type = vul_type
        self.pc = pc
        self.description = description

    def __eq__(self, other):
        return self.vul_type == other.vul_type and self.pc == other.pc

    def __str__(self):
        return "{}: pc {}".format(self.vul_type, str(self.pc))

class Detector():
    def __init__(self):
        self.oracles = []

    def _run_oracle(self, trace):
        result = {}
        for oracle in self.oracles:
            result[oracle.name] = oracle.run(trace)
        return result

    @abstractmethod
    def _run_detector(self, result):
        return None # return Vulnerability object

    def run(self, trace):
        result = self._run_oracle(trace)
        return self._run_detector(result)