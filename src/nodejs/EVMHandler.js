const Web3 = require('web3');
const solc = require('solc');
const remixDebugger = require('remix-debug').EthDebugger;
const BreakpointManager = require('remix-debug').BreakpointManager
const utileth = require('ethereumjs-util')
const Tx = require('ethereumjs-tx')
const Block = require('ethereumjs-block')
const BN = require('ethereumjs-util').BN
const remixLib = require('remix-lib')
const Debugger = require('remix-debug').EthDebugger

privateKeys = [
  Buffer.from('c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3', 'hex'),
  Buffer.from('ae6ae8e5ccbfb04590405997ee2d52d2b330726137b875053c36d94e974d162f', 'hex'),
  Buffer.from('0dbbe8e4ae425a6d2687f1a7e3ba17bc98c673636790f1b8ad91193c05875ef1', 'hex'),
  Buffer.from('c88b703fb08cbea894b6aeff5a544fb92e78a18e19814cd85da83b71f772aa6c', 'hex'),
  Buffer.from('388c684f0ba1ef5017716adb5d21a053ea8e90277d0868337519f97bede61418', 'hex'),
  Buffer.from('659cbb0e2411a44db63778987b1e22153c086a95eb6b18bdf89de078917abc63', 'hex'),
  Buffer.from('82d052c865f5763aad42add438569276c00d3d88a2d062d36b2bae914d58b8c8', 'hex'),
  Buffer.from('aa3680d5d48a8283413f7a108367c7299ca73f553735860a87b08f39395618b7', 'hex'),
  Buffer.from('0f62d96d6675f32685bbdb8ac13cda7c23436f63efbb9d07700d8669ff12b7c4', 'hex'),
  Buffer.from('8d5366123cb560bb606379f90a0bfd4769eecc0557f1b362dcae9012b548b1e5', 'hex')
]

EVMHandler = {
  // debuggers provided by Remix
  debugger: null,
  // virtual machine implemented by js
  vm: null,
  // web3 object corresponding to vm
  web3vm: null,
  // a map from address to private keys
  accounts: {},
  defaultAccount: null,
  contracts: {},
  // currently use web3 as utils
  web3: new Web3(),
  // a nonce
  t: 12,

  // compile a contract source to a contract object
  compile: (source, name) => {
    let filename = "filename";
    let output = solc.compile({ 'sources': { filename: source } }, 1);
    let contract_name = filename + ":" + name;
    let contract = output.contracts[contract_name];
    return contract;
  },

  init: () => {
    EVMHandler.vm = EVMHandler.initVM()
    EVMHandler.web3vm = new remixLib.vm.Web3VMProvider()
    EVMHandler.web3vm.setVM(EVMHandler.vm)
    EVMHandler.debugger = new Debugger({
      web3: EVMHandler.web3vm,
      compilationResult: function () {
        return true;
      }
    })
    // EVMHandler.debugger.addProvider('web3vmprovider', EVMHandler.web3VM)
    // EVMHandler.debugger.switchProvider('web3vmprovider')
  },

  initVM: () => {
    let utileth = require('ethereumjs-util')
    let VM = require('ethereumjs-vm')
    let Web3Providers = remixLib.vm.Web3Providers
    let vm = new VM({
      enableHomestead: true,
      activatePrecompiles: true
    })
    EVMHandler.accounts = [];
    for (let i in privateKeys) {
      let address = utileth.privateToAddress(privateKeys[i])
      vm.stateManager.putAccountBalance(address, 'f00000000000000001', function cb () {})
      EVMHandler.accounts[utileth.bufferToHex(address)] = privateKeys[i].toString('hex');
      if (i == 0) {
        EVMHandler.defaultAccount = utileth.bufferToHex(address);
      }
    }
    let web3Providers = new Web3Providers()
    web3Providers.addVM('VM', vm)
    web3Providers.get('VM', function (error, obj) {
      if (error) {
        let mes = 'provider TEST not defined'
        console.log(mes)
        st.fail(mes)
      } else {
        vm.web3 = obj
      }
    })
    return vm
  },

  // deploy a new contract; take compiled contract from solc as input
  deploy: (contract) => {
    return new Promise((resolve, reject) => {
      let accs = Object.keys(EVMHandler.accounts)
      EVMHandler.sendTx(EVMHandler.defaultAccount, "", 0, contract.bytecode).then((result) => {
        if (!result.tx.contractAddress) reject(Error("Invalid contract address"));
        EVMHandler.contracts[result.tx.contractAddress] = contract;
        resolve(result);
      }).catch((err) => {
        reject(err)
      })
    });
  },

  debug: (tx) => {
    return new Promise((resolve, reject) => {
      EVMHandler.debugger.debug(tx);
      resolve(EVMHandler.debugger.traceManager.trace)
      // EVMHandler.debugger.event.register('newTraceLoaded', () => {
      //   // start doing basic stuff like retrieving step details
      //   EVMHandler.debugger.traceManager.getCallStackAt(34, (error, callstack) => {})
      // })
    });
  },

  // send a raw transaction
  sendTx: (from, to, value, data) => {
    return new Promise((resolve, reject) => {
      let tx = new Tx({
        nonce: new BN(from.nonce++),
        gasPrice: new BN(1),
        gasLimit: new BN(3000000, 10),
        to: to,
        value: new BN(value, 10),
        data: Buffer.from(data, 'hex')
      })
      tx.sign(Buffer.from(EVMHandler.accounts[from], 'hex'));
      let block = new Block({
        header: {
          timestamp: new Date().getTime() / 1000 | 0,
          number: 0
        },
        transactions: [],
        uncleHeaders: []
      })
      EVMHandler.vm.runTx({block: block, tx: tx, skipBalance: true, skipNonce: true}, function (error, result) {
        if (error) reject(error)
        txHash = utileth.bufferToHex(tx.hash());
        EVMHandler.web3vm.eth.getTransaction(txHash, (err, evmTx) => {
          if (err) {
            reject(err);
          } else {
            resolve({tx: evmTx, res: result});
          }
        })
      })
    });
  },

  // send transaction with formatted inputs
  sendFormatTx: (from, to, value, func, args) => {
    let abi = JSON.parse(EVMHandler.contracts[to].interface)
    let funcAbi = null;
    for(let i in abi) {
      if (abi[i]["name"] == func) {
        funcAbi = abi[i];
      }
    }
    if (!funcAbi) return Error("function not found");
    let payload = EVMHandler.web3.eth.abi.encodeFunctionCall(funcAbi, args);
    return EVMHandler.sendTx(from, to, value, payload);
  }
}

module.exports = EVMHandler;