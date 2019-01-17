const path = require('path');
const grpc = require('grpc');
const protoLoader = require('@grpc/proto-loader');
const PROTO_PATH = path.join(__dirname, '../static/evm.proto');

let evmHandler = require('./EVMHandler');
evmHandler.init();

// Suggested options for similarity to existing grpc.load behavior
let packageDefinition = protoLoader.loadSync(
    PROTO_PATH,
    {keepCase: true,
     longs: String,
     enums: String,
     defaults: true,
     oneofs: true
    });
let protoDescriptor = grpc.loadPackageDefinition(packageDefinition);
// The protoDescriptor object has the full package hierarchy
let evm = protoDescriptor.evm;

function resetWrapper(status) {
  evmHandler.init();
  return { option: status.option }
}

function getAccountsWrapper(status) {
  evmHandler.getAccounts().then((accs) => {
    return {
      data: JSON.stringify(accs)
    }
  }).catch((err) => {
    return { data: "" }
  })
}

function compileWrapper(sourceObj) {
  let text = sourceObj.text;
  let name = sourceObj.name;
  try {
    let contract = evmHandler.compile(text, name);
    return {
      data: JSON.stringify(contract)
    };
  } catch (err) {
    console.log(err)
    return {
      data: ""
    };
  } 
}

function deployWrapper(contractObj) {
  let contract = null;
  try {
    contract = JSON.parse(contractObj);
  } catch (err) {
    console.log("Invalid json format")
    return { address: "" };
  }
  if (contract == null) {
    console.log("fail to extract contract object");
    return { address: "" };
  }
  evmHandler.deploy(contract).then((res) => {
    return {
      address: res.tx.contractAddress
    }
  }).catch((err) => {
    console.log(err);
    return { address: "" };
  })
}

function sendTxWrapper(sendTxData) {
  evmHandler.sendTx(sendTxData.from, sendTxData.to, sendTxData.value, sendTxData.data).then((trace) => {
    return {
      data: JSON.stringify(trace)
    }
  }).catch((err) => {
    return { data: "" }
  })
}

function getServer() {
  var server = new grpc.Server();
  server.addService(evm.EVM.service, {
    reset: resetWrapper,
    getAccounts: getAccountsWrapper,
    compile: compileWrapper,
    deploy: deployWrapper,
    sendTx: sendTxWrapper
  });
  return server;
}

var evmServer = getServer();
evmServer.bind('0.0.0.0:50051', grpc.ServerCredentials.createInsecure());
evmServer.start();
console.log("server listening ...")
