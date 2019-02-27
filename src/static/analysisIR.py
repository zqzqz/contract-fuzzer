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
    1）address
    2) uint256 (
    3) mapping
    4) bool (usually used with require)

refer to: https://solidity.readthedocs.io/en/latest/types.html
    
值类型包括:
未考虑：
* 定长浮点型 (Fixed Point Numbers)
* 定长字节数组 (Fixed-size byte arrays)
* 字符串字面量（String literals）
* 十六进制字面量（Hexadecimal literals）
* 枚举 (Enums)
* 函数 (Function Types) <--不归入此类别
* 地址字面量 (Address Literals)

引用类型包括：
* 不定长字节数组（bytes）
* 字符串（string）
* 数组（Array）
以上均当作map处理
未考虑：
* 结构体（Struts）  

    
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
token:
[ lineno, [ wordtype, word ] ]
if wordtype is var:
[ lineno, [ wordtype, word ], vartype ]

lineno --> number like: [ lineno, con_no, fun_no, expr_no, ir_no]

vartype can be:
1) address 
2) uint256
3) ['mapping', name]
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
        Operator = r'(?P<Operator>\+=|\+|--|-=|\*=|:=|/|->|-)'

        # delimiters (not neccessary for IR)
        Separator = r'(?P<Separator>[)(,\[\]])'

        # numbers
        Number = r'(?P<Number>\d+[.]?\d+)'

        # variable type
        varType = r'(?P<varType>address|uint256|mapping)'
        # In fact, don't deal with mapping type at this state

        # system variable
        sysVar = r'(?P<sysVar>msg.sender|msg.value|this.balance)'

        # intermediate variable
        interVar = r'(?P<interVar>TMP_[0_9]+|REF_[0-9]+|TMP|REF)'

        # name of variable
        ID = r'(?P<ID>[a-zA-Z_][a-zA-Z_0-9]*)'

        # certain functions of IR
        Method = r'(?P<Method>(main){1}|(printf){1})'

        # Error = r'(?P<Error>.*\S+)'
        Error = r'\"(?P<Error>.*)\"'

        # attention: front | behind have difference

        this.patterns = re.compile('|'.join([Keyword, Method, varType, sysVar, interVar, ID, Number, Separator, Operator, Error]))

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
        filter for dropping expression with 'IRs:' and keep irs;
        transform tuple into list
        distinguish different types of ID;
        '''
        dropLine = []
        changeLineno = 0
        conLine = []
        funLine = []
        exprLine = []
        irLine = []
        lst = iter(range(len(this.results)))
        for i in lst:
            if (this.results[i][1][1] == 'Expression:'):
                exprLine.append(this.results[i][0]-changeLineno)
                irLine.append(this.results[i+1][0])
                dropLine.extend([this.results[i][0],this.results[i][0]+1])
                changeLineno += 2
            if not(this.results[i][0] in dropLine):
                this.results[i][0] -= changeLineno
                if (this.results[i][1][1] == 'Contract'):
                    conLine.append(this.results[i][0])
                    this.final.append([this.results[i][0], [this.results[i][1][0], this.results[i][1][1]]])
                    this.final.append([this.results[i+1][0]-changeLineno,['conID',this.results[i+1][1][1]]])
                    lst.__next__()
                elif (this.results[i][1][1] == 'Function'):
                    funLine.append(this.results[i][0])
                    this.final.append([this.results[i][0], [this.results[i][1][0], this.results[i][1][1]]])
                    this.final.append([this.results[i+1][0]-changeLineno, ['funID', this.results[i+1][1][1]]])
                    lst.__next__()
                else:
                    this.final.append([this.results[i][0], [this.results[i][1][0], this.results[i][1][1]]])

        print('original IR tokens:\n',this.final)
        print('lineno:\n',[conLine,funLine,exprLine])
        exprLine_copy = exprLine[:]

        '''
        number transform
        format: [lineno, contractNum, functionNum, exprNum, irNum]
        '''
        [contractNum, functionNum, exprNum, irNum] = [0,0,0,0]
        for i in range(len(this.final)):
            if (this.final[i][0] in conLine):
                contractNum += 1
                del conLine[0]
                functionNum = 0
                this.final[i][0] = [this.final[i][0],contractNum,0,0,0]
            elif (this.final[i][0] in funLine):
                functionNum += 1
                del funLine[0]
                exprNum = 0
                this.final[i][0] = [this.final[i][0],contractNum,functionNum,0,0]
            elif (this.final[i][0] in exprLine):
                exprNum += 1
                del exprLine[0]
                this.final[i][0] = [this.final[i][0],contractNum,functionNum,exprNum,1]
            else: this.final[i][0] = [this.final[i][0],this.final[i-1][0][1],this.final[i-1][0][2],this.final[i-1][0][3],this.final[i-1][0][4]]

        print('Number version:\n', this.final)
        print('sssss\n',exprLine_copy)
        add = 0
        for i in range(len(this.final)):
            if (i==0): pass
            elif (this.final[i][0][4] == 1) and (this.final[i-1][0][4] != 0):
                if (this.final[i-1][0][0] != this.final[i][0][0]):
                    add +=1
                if (this.final[i][0][0] in exprLine_copy): add = 0
                this.final[i][0][4] += add

        print('newNumber version:\n',this.final)


        '''
        combine with ID and its type;
        drop the '(' and ')' for variable type
        '''
        dropToken = []
        for i in range(len(this.final)):
            if (i<len(this.final)-1): # for the case like 'RETURN msg.sender' as last token
                if (this.final[i][1][0] in ['ID','sysVar','interVar']) and (this.final[i+1][1][1] == '(') and (this.final[i+2][1][1] != '->'):
                    type = this.final[i+2][1][1]
                    this.final[i].append(type)
                    dropToken.extend([i+1,i+2,i+3])
        for i in range(len(dropToken)):
            del this.final[dropToken[i]]
            for j in range(len(dropToken)):
                dropToken[j] -= 1

        print('drop type token:\n',this.final)

        '''
        deal with mapping, take [ ] as index, like:
        REFERENCE -> LVALUE [ RVALUE ]
        start with '->'
        '''

        dropNum = []
        for i in range(len(this.final)):
            if (this.final[i][1][1] == '->'):
                if (this.final[i - 1][1][1] != '('):
                    dropNum.extend([i+2,i+3,i+4])
                    # this.final[i+1][1][0] = 'Mapping'
                    this.final[i+1][1].append(this.final[i+3][1][1])
                    this.final[i+1].append(['mapping',this.final[i+1][1][1]])
                else:
                    this.final[i-2].append(['mapping','balance'])
                    dropNum.extend([i-1,i+1,i+2])



        for i in range(len(dropNum)):
            del this.final[dropNum[i]]
            for j in range(len(dropNum)):
                dropNum[j] -= 1


        '''
        deal with ':='
        '''
        eqNum = []
        for i in range(len(this.final)):
            if (this.final[i][1][1] in [':=','->']):
                eqNum.append(i)
        # In the same line, the ID on the left side of ':=' means write, the ID on the right side means read
        # I am not sure whether this way is right
        read = []
        write = []
        for i in eqNum:
            j = i
            lineNum = this.final[i][0]
            while (True):
                j += 1
                if (this.final[j][1][0] in ['ID','sysVar','Mapping']) :
                    read.append(this.final[j])
                if (this.final[j]!=lineNum): break
            j = i
            while (True):
                j -= 1
                if (this.final[j][1][0] in ['ID','sysVar','Mapping']):
                    write.append(this.final[j])
                if (len(this.final[j])==3):
                    if (this.final[j][2][0] == 'Mapping'):
                        write.append(this.final[j])
                if (this.final[j]!=lineNum): break

        print('total tokens:\n',this.final)
        print('read:\n',read)
        print('write:\n',write)

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

        '''
        drop lineno
        drop repeated var in read and write list
        '''
        for i in range(len(read)):
            if not(read[i][1] in this.readList):
                this.readList.append(read[i][1])
        for i in range(len(write)):
            if not(write[i][1] in this.writeList):
                this.writeList.append(write[i][1])

        print('readlist:\n',this.readList)
        print('writelist:\n',this.writeList)





if __name__ == '__main__':
    token = Token()
    # filepath = "outIR.txt"
    filepath = "testIR.txt"

    lines = token.read_file(filepath)
    # print(lines)

    for line in lines:
        token.write_file(token.run(line), "results.txt")
        token.lineno += 1

    print(token.results)
    token.transform()
    print('simplified token:\n', token.final)

'''
Next goal:
（1）function <--> function
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
