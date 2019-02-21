#!/usr/bin/python
import os
import re

# keywords type
'''
1. Topic Keywords (TopKey)
    1) 1st level: Contract <== contract
    2) 2nd level: Function <== fun
    3) 3rd level: 
        a) Expression 
        b) IRs
   
2. Syntax Keywords (SynKey)
   refer to slither Doc
   https://github.com/trailofbits/slither/wiki/SlithIR

3. name of variable
    1) TMP_[1..9]* <== TMP_ID
    2) REF_[1..9]* <== REF_ID
    3) Others <== Var_ID

4. Operator: 
    :=,!=, +,-,*,/, **, ->, &,|,^,<,>, &&, --
    1) assignment: :=
    2) binary oper: **,+,-,*,/,<<,>>,&,^,|,>,<,>=,<=,==,!=,,&&,--
    3) unary oper: !,~
    4) index: LVALUE [ RVALUE ]
    5) member:
        a)REFERENCE -> LVALUE . RVALUE
        b)REFERENCE -> CONTRACT . RVALUE
        c)REFERENCE -> ENUM . RVALUE
    6) new oper
    7) push oper
    8) delete oper
    9）conversion
    CONVERT LVALUE RVALUE TYPE
    10) unpack
    11) array initialization
    12) call oper
    13) return
    14) condition
5. variable type (varType)
    ([address/unint256...],[][])
    
6. system variable (sysVar0
    1) msg
        a) .sender
        b) .value
    2) this
        a) .balance    

6. delimiters (Separator)
    
'''

# output format
'''
token.results=[result0,result1,...]
result = [lineno,(type,word)]
'''

class Token(object):

    # initialization
    def __init__(this):
        # list for the result of token
        this.results = []

        # line number
        this.lineno = 1

        # basic keywords
        this.keywords = ['Contract','Function','Expression:','IRs:']

        # Keywords
        Keyword = r'(?P<Keyword>(Contract){1}|(Function){1}|(Expression:){1}|(IRs:){1})'

        # operations
        Operator = r'(?P<Operator>\+=|\+|--|-=|-|\*=|:=|/)'

        # delimiters (not neccessary for IR)
        Separator = r'(?P<Separator>[)(,\[\]])'

        # numbers
        Number = r'(?P<Number>\d+[.]?\d+)'

        # variable type
        varType = r'(?P<varType>address|uint256)'

        # system variable
        sysVar = r'(?P<sysVar>msg.sender|msg.value|this.balance)'

        # name of variable
        ID = r'(?P<ID>[a-zA-Z_][a-zA-Z_0-9]*)'

        # certain functions of IR
        Method = r'(?P<Method>(main){1}|(printf){1})'

        # Error = r'(?P<Error>.*\S+)'
        Error = r'\"(?P<Error>.*)\"'

        this.patterns = re.compile('|'.join([Keyword, Method, varType, sysVar, ID, Number, Separator, Operator, Error]))

    # read the file, return the list of lines
    def read_file(this, filename):
        with open(filename, "r") as fin:
            return [line.strip() for line in fin]

    # write the result into file
    def write_file(this, lines, filename='results.txt'):
        with open(filename, "a") as fout:
            for line in lines:
                if line:
                    fout.write(line)
                else:
                    continue

    def get_token(this, line):
        for match in re.finditer(this.patterns, line):
            yield (match.lastgroup, match.group())

    def run(this, line):
        result = []
        for token in this.get_token(line):
            result.append(this.lineno)
            result.append(token)
            this.results.append(result)
            result=[]
            yield "line %3d :" % this.lineno + str(token) + "\n"

if __name__ == '__main__':
    token = Token()
    filepath = "outIR.txt"

    lines = token.read_file(filepath)
    print(lines)

    for line in lines:
        token.write_file(token.run(line), "results.txt")
        token.lineno += 1

    print(token.results)


'''
Next goal:
Function withdraw()
	Expression: require(bool)(msg.sender.call.value(balances[msg.sender])())
	IRs:
		REF_4(uint256) -> balances[msg.sender]
		TMP_3(bool) = LOW_LEVEL_CALL, dest:msg.sender, function:call, arguments:[] value:REF_4 
		TMP_5 = SOLIDITY_CALL require(bool)(TMP_3)
	Expression: balances[msg.sender] = 0
	IRs:
		REF_5(uint256) -> balances[msg.sender]
		REF_5 (->balances) := 0(uint256)
'''
