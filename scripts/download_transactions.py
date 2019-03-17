import requests
from bs4 import BeautifulSoup
import os
import re
import json
import sys
import threading
import queue
import time

target_path = "/mnt/data/contracts/transactions"
source_path = "/mnt/data/contracts/source"

queueLock = threading.Lock()
workQueue = queue.Queue(50000)
threads = []
exitFlag = 0
threadNum = 10

def downloadOne(filename):
    print("entering", filename)
    address = filename.split('#')[0]

    # page = "https://etherscan.io/txs?a="+address+"&f=3"
    # req = requests.get(page)
    # soup = BeautifulSoup(req.text, "lxml")
    # total = int(soup.find(name="span", attrs={"class": "hidden-xs"}).text.split()[3])
    # max_page = total//100+1
    max_page = 1
    contractObj = []
    txCnt = 0

    for pageNum in range(1, max_page+1):
        page = "https://etherscan.io/txs?a="+address+"&f=3&ps=100&p="+str(pageNum)

        try:
            req = requests.get(page)
            soup = BeautifulSoup(req.text, "lxml")
            
            trs = soup.table.tbody.find_all("tr")
            if len(trs) <=2 and "There are no mataching entries" in trs[0].text:
                break
        except:
            break
        
        for tr in trs:
            try:
                txHash = tr.find_all(name="span", attrs={"class":"hash-tag"})[0].text
                txObj = {}
                txPage = "https://etherscan.io/tx/"+txHash
                txReq = requests.get(txPage)
                soup = BeautifulSoup(txReq.text, "lxml")
                if len(soup.find_all(name="i", attrs={"class": "fa fa-check-circle-o", "rel": "tooltip"})) > 0:
                    txObj['status'] = True
                elif len(soup.find_all(name="i", attrs={"class": "fa fa-exclamation-triangle", "rel": "tooltip"})) > 0:
                    txObj['status'] = False
                else:
                    txObj['status'] = None
                txObj['id'] = txCnt
                txObj['hash'] = txHash
                txObj['from'] = soup.find(name="div", text="From:").find_next('div').find("a").text
                txObj['value'] = soup.find(name="div", text="Value:").find_next('div').find("span").text.split()[0]
                txObj['data'] = soup.find(name="div", text="Input Data:").find_next('div').find(name="span", attrs={"id": "rawinput"}).text
                txObj['args'] = []
                argsTabs = soup.find(name="div", attrs={"id": "inputDecode"}).find_next('tbody').find_all('tr')
                print(soup.find(name="div", attrs={"id": "inputDecode"}))
                # for arg in argsTabs:
                #     argTds = arg.find_all('td')
                #     print(argTds)
                #     try:
                #         argObj = {}
                #         argObj["id"] = argTds[0].text
                #         argObj["name"] = argTds[1].text
                #         argObj["type"] = argTds[2].text
                #         argObj["data"] = argTds[3].text
                #         txObj['args'].append(argObj)
                #     except:
                #         continue

                contractObj.append(txObj)
                txCnt += 1
            except:
                continue
    print(contractObj)
    
    with open(os.path.join(target_path, filename), "w") as f:
        json.dump(contractObj, f)
    print('leaving', filename)

def oneThread(q):
    while exitFlag == 0:
        queueLock.acquire()
        if not workQueue.empty():
            filename = q.get()
            queueLock.release()
            downloadOne(filename)
        else:
            queueLock.release()
        time.sleep(1)


def downloadAll():
    global exitFlag
    filenames = os.listdir(source_path)

    # fill queue
    queueLock.acquire()
    for filename in filenames:
        if (os.path.exists(os.path.join(target_path, filename))):
            continue
        workQueue.put(filename)
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

#downloadOne("0x0c7b8eedd028f3730e7b0f3dc032e916302f09b4", 100)
downloadAll()