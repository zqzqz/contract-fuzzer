import requests
from bs4 import BeautifulSoup
import os
import re
import sys
import codecs

contract_url = "https://etherscan.io/address/ADDRESS#code"
contract_dir = "contracts"
contract_list = "vulnerable_contracts.txt"

def writeFile(filename, content):
    try:
        if not os.path.exists(filename):
            with codecs.open(filename, "w", encoding="utf-8") as f:
                f.write(content)
    except Exception as e:
        print("Writing", filename, str(e))

def readList(filename):
    try:
        if os.path.exists(filename):
            with open(filename, "r") as f:
                return f.read().split('\n')
    except Exception as e:
        print("Writing", filename, str(e))

def downloadOneContract(address):
    print("Contract:", address)
    url = contract_url.replace("ADDRESS", address)
    req = requests.get(url)
    soup = BeautifulSoup(req.text, "lxml")
    
    name = soup.find_all(name="span", attrs={"class": "h6 font-weight-bold mb-0"})[0].text
    code = soup.select('pre')
    source = code[0].text

    filename = address + "#" + name + ".sol"
    writeFile(os.path.join(contract_dir, filename), source)

    print("Leave contract:", address)

def main():
    addr_list = readList(contract_list)
    for address in addr_list:
        downloadOneContract(address)

if __name__ == '__main__':
    main()


