"""python interface for evm functions"""

import json
import grpc
import os

import evm_pb2
import evm_pb2_grpc

channel = grpc.insecure_channel('localhost:50051')
stub = evm_pb2_grpc.EVMStub(channel)

def reset(option=0):
    status = evm_pb2.Status(option=option)
    ret = stub.Reset(status)
    return ret.option

def getAccounts(option=0):
    status = evm_pb2.Status(option=option)
    ret = None
    for i in stub.GetAccounts(status):
        ret = i.data
        break
    if not ret or len(ret) > 0:
        return json.loads(ret)
    else:
        return None

def compile(text, name):
    source = evm_pb2.Source(text=text, name=name)
    ret = stub.Compile(source)
    print(ret.data)
    if not ret or len(ret.data) > 0:
        return json.loads(ret.data)
    else:
        return None

def deploy(contract):
    contractRpc = evm_pb2.Json(data=json.dumps(contract))
    ret = None
    for i in stub.Deploy(contractRpc):
        ret = i.address
        break
    return ret

def sendTx(fromAddr, toAddr, value, data):
    sendTxData = evm_pb2.sendTxData(fromAddr=fromAddr, toAddr=toAddr, value=value, data=data)
    ret = None
    for i in stub.SendTx(sendTxData):
        ret = i.data
        break
    if not ret or len(ret) > 0:
        return json.loads(ret)
    else:
        return None


def test():
    with open(os.path.join(os.getcwd(), '../static/Test.sol'), 'r') as f:
        text = f.read()
    print("\ncontract\n")
    print(text)
    print("\nTesting getAccounts:\n")
    accounts = getAccounts()
    print(accounts)
    print("\nTesting compile\n")
    contract = compile(text, "Test")
    print(contract)
    print("\nTesting deploy\n")
    address = deploy(contract)
    print(address)

if __name__ == "__main__":
    test()
