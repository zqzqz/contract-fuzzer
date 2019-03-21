# parent class: detector
# https://github.com/gongbell/ContractFuzzer/blob/807b76177a9509b13cd409eb0a71e9e15322f2a1/go-ethereum-cf/core/vm/hacker_oracle.go

class DetectionManager():
    def __init__(self):
        self.detectors = []

    def run(self, traces):
        report = []
        for trace in traces:
            for detector in self.detectors:
                vul = detector.run(trace)
                if vul != None and vul not in report:
                    report.append(vul)
        return report