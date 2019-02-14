#!/usr/bin/python
import os
import re

class Token(object):

    # initialization
    def __init__(this):
        # list for the result of token
        this.results = []

        # line number
        this.lineno = 1

        # basic keywords
        # this.keywords = ['Contract','Function','Expression','IRs','condition','_receiver','balance']
        this.keywords = ['auto', 'struct', 'if', 'else', 'for', 'do', 'while', 'const',
                         'int', 'double', 'float', 'long', 'char', 'short', 'unsigned',
                         'switch', 'break', 'defalut', 'continue', 'return', 'void', 'static',
                         'auto', 'enum', 'register', 'typeof', 'volatile', 'union', 'extern']
        '''
    regex中：*表示从0-， +表示1-， ？表示0-1。对应的需要转义
    { 表示限定符表达式开始的地方 \{
    () 标记一个子表达式的开始和结束位置。子表达式可以获取共以后使用：\( \)
    r表示原生字符串。
    '''
        # Keywords
        Keyword = r'(?P<Keyword>(auto){1}|(double){1}|(int){1}|(if){1}|(#include){1}|(return){1}|(char){1}|(stdio\.h){1}|(const){1})'
        # operations := + - * ** /
        Operator = r'(?P<Operator>\+\+|\+=|\+|--|-=|-|\*=|/=|/|%=|%)'

        # delimiters (not neccessary for IR)
        Separator = r'(?P<Separator>[,:\{}:)(<>])'

        # numbers
        Number = r'(?P<Number>\d+[.]?\d+)'

        # name of variable
        ID = r'(?P<ID>[a-zA-Z_][a-zA-Z_0-9]*)'

        # certain functions of IR
        Method = r'(?P<Method>(main){1}|(printf){1})'

        # Error = r'(?P<Error>.*\S+)'
        Error = r'\"(?P<Error>.*)\"'

        this.patterns = re.compile('|'.join([Keyword, Method, ID, Number, Separator, Operator, Error]))

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

    def run(this, line, flag=True):
        for token in this.get_token(line):
            if flag:
                print("line %3d :" % this.lineno, token)
            else:
                yield "line %3d :" % this.lineno + str(token) + "\n"


    def printrun(this, line, flag=True):
        for token in this.get_token(line):
            if flag:
                print("lines x: ", token)


if __name__ == '__main__':
    token = Token()
    filepath = "test.c"

    lines = token.read_file(filepath)
    print(lines)

    for line in lines:
        # token.run(line, True)
        token.write_file(token.run(line, False), "results.txt")
        token.lineno += 1

