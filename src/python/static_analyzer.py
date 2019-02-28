from ir_analyzer import Visitor, IrAnalyzer
import logging

class StaticAnalyzer(IrAnalyzer):
    def __init__(self, filename=None):
        super().__init__(filename)

    # todo