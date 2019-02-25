#!/usr/bin/python3
from __future__ import print_function
import os
import subprocess

# print("Current directory: ",os.getcwd())

conArr = os.listdir('./contracts')
conPath = []
irArr = []
f = open("outIR.txt",'wb+')

for i in range(len(conArr)):
    conPath.append(os.path.join(os.path.abspath('./contracts'),conArr[i]))
    irArr.append(subprocess.check_output(["slither",conPath[i],"--print","slithir"]))
    f.write(irArr[i])

print("conList is:/n",conArr)
