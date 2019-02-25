import os
import re

# keywords type
'''
1. Topic Keywords (TopKey)
    1) 1st level: Contract <== contract and conID
    2) 2nd level: Function <== fun and funID
    3) 3rd level: 
        a) Expression 
        b) IRs
   
2. Syntax Keywords (SynKey)
   refer to slither Doc
   https://github.com/trailofbits/slither/wiki/SlithIR

3. name of variable
    1) TMP_[1..9]* <== TMP_ID
    2) REF_[1..9]* <== REF_ID
    3) Others <== ID

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
        this.final = []

        # list for read and write
        this.readList = []
        this.writeList = []

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

    def transform(this):
        '''
        filter for dropping expression and keep irs;
        transform tuple into list
        distinguish different types of ID;
        '''
        dropLineno = []
        changeLineno = 0
        lst = iter(range(len(this.results)))
        for i in lst:
            if (this.results[i][1][1] == 'Expression:'):
                dropLineno.append(this.results[i][0])
                changeLineno += 1
            if not(this.results[i][0] in dropLineno):
                this.results[i][0] -= changeLineno
                if (this.results[i][1][1] == 'Contract'):
                    this.final.append([this.results[i][0], [this.results[i][1][0], this.results[i][1][1]]])
                    this.final.append([this.results[i+1][0],['conID',this.results[i+1][1][1]]])
                    lst.__next__()
                elif (this.results[i][1][1] == 'Function'):
                    this.final.append([this.results[i][0], [this.results[i][1][0], this.results[i][1][1]]])
                    this.final.append([this.results[i+1][0], ['funID', this.results[i+1][1][1]]])
                    lst.__next__()
                else:
                    this.final.append([this.results[i][0], [this.results[i][1][0], this.results[i][1][1]]])

        # print(this.final)

        '''
        combine with ID and its type;
        drop the '(' and ')' for variable type
        '''
        dropToken = []
        for i in range(len(this.final)):
            if (this.final[i][1][0] in ['ID','sysVar']):
                type = this.final[i+2][1][1]
                this.final[i].append(type)
                dropToken.extend([i+1,i+2,i+3])
        for i in range(len(dropToken)):
            del this.final[dropToken[i]]
            for j in range(len(dropToken)):
                dropToken[j]-=1

        # print(this.final)

        '''
        deal with ':='
        '''
        eqNum = []
        for i in range(len(this.final)):
            if (this.final[i][1][1] == ':='):
                eqNum.append(i)
        # In the same line, the ID on the left side of ':=' means write, the ID on the right side means read
        # I am not sure whether this way is right
        for i in eqNum:
            j = i
            lineNum = this.final[i][0]
            while (True):
                j -= 1
                if (this.final[j][1][0] in ['ID','sysVar']) :
                    this.readList.append(this.final[j])
                if (this.final[j]!=lineNum): break
            j = i
            while (True):
                j += 1
                if (this.final[j][1][0] in ['ID','sysVar']):
                    this.writeList.append(this.final[j])
                if (this.final[j]!=lineNum): break

        print('total tokens:\n',this.final)
        print('read:\n',this.readList)
        print('write:\n',this.writeList)

        '''
        drop all the operators
        '''
        dropOper = []
        for i in range(len(this.final)):
            if (this.final[i][1][0] == 'Operator'):
                dropOper.append(i)
        for i in range(len(dropOper)):
            del this.final[dropOper[i]]
            for j in range(len(dropOper)):
                dropOper[j] -= 1

if __name__ == '__main__':
    token = Token()
    # filepath = "outIR.txt"
    filepath = "testIR.txt"

    lines = token.read_file(filepath)
    # print(lines)

    for line in lines:
        token.write_file(token.run(line), "results.txt")
        token.lineno += 1

    # print(token.results)
    token.transform()
    print('simplified token:\n', token.final)

'''
Next goal:

（1）take [] into consideration

（2）function <--> function
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
