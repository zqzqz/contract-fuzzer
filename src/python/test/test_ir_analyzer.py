import sys
sys.path.append("..")
from ir_analyzer import *
import os

def test():
    filename = os.path.join(os.getcwd(), '../../static/Test.sol')
    ir_analyzer = IrAnalyzer(filename)
    visitor = Visitor(None, None, None, None)
    ir_analyzer.parse_contracts(visitor)

if __name__ == "__main__":
    test()