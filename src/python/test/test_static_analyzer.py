import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from static_analyzer import *

def test():
    filename = os.path.join(os.path.dirname(__file__), '../../static/test/Test.sol')
    analyzer = StaticAnalyzer(filename, "Test")
    report = analyzer.run(debug=1)
    print("encoded report:", report)

if __name__ == "__main__":
    test()