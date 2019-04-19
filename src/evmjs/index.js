const path = require('path');
const grpc = require('grpc');
const protoLoader = require('@grpc/proto-loader');
const PROTO_PATH = path.join(__dirname, '../static/evm.proto');

let evmHandler = require('./EVMHandler');
evmHandler.init().then(() => {
  console.log("initVM success");
})

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

async function resetWrapper(call) {
  await evmHandler.init();
  call.write({ option: call.request.option });
  call.end()
}

async function getAccountsWrapper(call) {
  try {
    let accs = await evmHandler.getAccounts();
    call.write({
      data: JSON.stringify(accs)
    });
    call.end();
  } catch (err) {
    call.end();
  }
}

function compileWrapper(sourceObj) {
  let text = sourceObj.text;
  let name = sourceObj.name;
  try {
    let contract = evmHandler.compile(text, name);
    let sim_contract = {}
    if (contract.interface) sim_contract.interface = contract.interface
    if (contract.functionHashes) sim_contract.functionHashes = contract.functionHashes
    if (contract.bytecode) sim_contract.bytecode = contract.bytecode
    if (contract.opcodes) sim_contract.opcodes = contract.opcodes
    return {
      data: JSON.stringify(sim_contract)
    };
  } catch (err) {
    console.log(err)
    return { data: "" };
  } 
}

async function deployWrapper(call) {
  let contract = null;
  try {
    contract = JSON.parse(call.request.data);
    let res = await evmHandler.deploy(contract)
    call.write({
      address: res.address
    });
    call.end();
  } catch (err) {
    console.log(err)
    call.end();
  }
}

async function sendTxWrapper(call) {
  try {
    if (call.request.opts == 0) revertCallFlag = false
    else revertCallFlag = true
    let res = await evmHandler.sendTx(call.request.fromAddr, call.request.toAddr, call.request.value, call.request.data, revertCallFlag);
    let trace = await evmHandler.debug(res.tx);
    call.write({
      data: JSON.stringify(trace)
    });
    call.end();
  } catch (err) {
    console.log(err);
    call.end();
  }
}

function getServer() {
  var server = new grpc.Server();
  server.addService(evm.EVM.service, {
    reset: resetWrapper,
    getAccounts: getAccountsWrapper,
    compile: (call, callback) => { callback(null, compileWrapper(call.request)); },
    deploy: deployWrapper,
    sendTx: sendTxWrapper
  });
  return server;
}

var evmServer = getServer();
evmServer.bind('0.0.0.0:50051', grpc.ServerCredentials.createInsecure());
evmServer.start();
console.log("server listening ...")

exports.server = getServer();