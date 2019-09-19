"""python interface for evm functions"""

import json
import grpc
import os
import logging

import pyfuzz.evm.evm_pb2
import pyfuzz.evm.evm_pb2_grpc

logger = logging.getLogger("EVM")

class EvmHandler():
    def __init__(self, endpoint='localhost:50051'):
        self.channel = grpc.insecure_channel(endpoint)
        self.stub = pyfuzz.evm.evm_pb2_grpc.EVMStub(self.channel)

    def reset(self, option=0):
        status = pyfuzz.evm.evm_pb2.Status(option=option)
        ret = self.stub.Reset(status)
        return

    def getAccounts(self, option=0):
        status = pyfuzz.evm.evm_pb2.Status(option=option)
        ret = None
        for i in self.stub.GetAccounts(status):
            ret = i.data
            break
        if ret and len(ret) > 0:
            return json.loads(ret)
        else:
            logger.error("Correct response not received from rpc server (getAccounts)")
            raise Exception("cannot fetch accounts")

    def compile(self, text, name):
        source = pyfuzz.evm.evm_pb2.Source(text=text, name=name)
        ret = self.stub.Compile(source)
        if ret and len(ret.data) > 0:
            return json.loads(ret.data)
        else:
            logger.error("Correct response not received from rpc server (compile)")
            raise Exception("cannot compile contract")

    def deploy(self, contract):
        if not contract:
            raise Exception("cannot deploy none contract")
        new_contract = {}
        if "bytecode" in contract:
            new_contract["bytecode"] = contract["bytecode"]
        else:
            raise Exception("Invalid contract format")
        if "interface" in contract:
            new_contract["interface"] = contract["interface"]
        else:
            raise Exception("Invalid contract format")
        contractRpc = pyfuzz.evm.evm_pb2.Json(data=json.dumps(new_contract))
        ret = None
        for i in self.stub.Deploy(contractRpc):
            ret = i.address
        if ret == None:
            raise Exception("cannot deploy contract")
        return ret

    def sendTx(self, fromAddr, toAddr, value, data, opts={}):
        sentOpts = 0
        if "revert" in opts and opts["revert"]:
            sentOpts += 1
        sendTxData = pyfuzz.evm.evm_pb2.SendTxData(fromAddr=fromAddr, toAddr=toAddr, value=value, data=data, opts=sentOpts)
        ret = None
        for i in self.stub.SendTx(sendTxData):
            ret = i.data
            break
        if ret and len(ret) > 0:
            return json.loads(ret)
        else:
            logger.error("Correct response not received from rpc server (sendTx)")
            raise Exception("cannot send transaction")
