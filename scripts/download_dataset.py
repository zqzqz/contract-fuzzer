import requests
from bs4 import BeautifulSoup
import os
import re
import json
import sys
import threading
import queue
import time
import codecs
# from exceptions import Exception

bytecode_path = "/mnt/data/contracts/bytecode"
source_path = "/mnt/data/contracts/source"
abi_path = "/mnt/data/contracts/abi"
page_url = "https://etherscan.io/contractsVerified/LABEL"
contract_url = "https://etherscan.io/address/ADDRESS#code"

queueLock = threading.Lock()
workQueue = queue.Queue(3000)
threads = []
exitFlag = 0
threadNum = 10

class Contract:
    def __init__(self, address, name="", source=None, abi=None, bytecode=None):
        self.address = address
        self.name = name
        self.source = source
        self.abi = abi
        self.bytecode = bytecode

def writeFile(filename, content):
    try:
        if not os.path.exists(filename):
            with codecs.open(filename, "w", encoding="utf-8") as f:
                f.write(content)
    except Exception as e:
        print("Writing", filename, str(e))

def downloadOneContract(contract):
    print("Contract:", contract.address, contract.name)
    url = contract_url.replace("ADDRESS", contract.address)
    req = requests.get(url)
    soup = BeautifulSoup(req.text, "lxml")
    code = soup.select('pre')
    try:
        contract.source = code[0].text
        contract.abi = code[1].text
        contract.bytecode = code[2].text
    except:
        return

    if not re.match("\A(0x)?[0-9a-fA-F]*\Z", contract.bytecode):
        return

    tmp_file = os.path.join(bytecode_path, contract.address+'#'+contract.name+".bytecode")
    writeFile(tmp_file, contract.bytecode)
    tmp_file = os.path.join(source_path, contract.address+'#'+contract.name+".sol")
    writeFile(tmp_file, contract.source)
    tmp_file = os.path.join(abi_path, contract.address+'#'+contract.name+".abi")
    writeFile(tmp_file, contract.abi)
    print("Leave contract:", contract.address, contract.name)

def downloadOnePage(label):
    url = page_url.replace("LABEL", str(label))
    req = requests.get(url)
    print("Page:",url)
    soup = BeautifulSoup(req.text, "lxml")
    link = soup.find_all(name="a", attrs={"class": 'address-tag'})
    for l in link:
        address = l.string
        name = l.parent.find_next_sibling().string.strip()
        contract = Contract(address, name)
        try:
            downloadOneContract(contract)
        except Exception as e:
            print("Inside contract", contract.address, str(e))
            
    print("Leave page:", label)
    

def oneThread(q):
    global exitFlag
    while not exitFlag:
        queueLock.acquire()
        if not workQueue.empty():
            label = q.get()
            queueLock.release()
            try:
                downloadOnePage(label)
            except Exception as e:
                print("Inside page", label, str(e))
        else:
            queueLock.release()
        time.sleep(1)


def downloadAll(start, pageNum):
    global exitFlag

    # fill queue
    queueLock.acquire()
    for i in range(start, pageNum+1):
        workQueue.put(i)
    queueLock.release()

    # create threads
    for threadId in range(threadNum):
        # thread = myThread(threadId, workQueue)
        thread = threading.Thread(target=oneThread, args=(workQueue,))
        threads.append(thread)
    
    for t in threads:
        t.start()
    
    # wait for empty queue
    while not workQueue.empty():
        pass
    exitFlag = 1
    
    # wait all thread to finish
    for t in threads:
        t.join()
    print("Exiting Main Thread")

#downloadOneContract("0x0c7b8eedd028f3730e7b0f3dc032e916302f09b4", 100)
# downloadOnePage(1)
downloadAll(846, 2000)
