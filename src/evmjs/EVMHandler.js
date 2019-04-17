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
const async = require('async')
const Trie = require('merkle-patricia-tree/secure.js')
const Account = require('ethereumjs-account')

privateKeys = [
  Buffer.from('c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3', 'hex'),
  Buffer.from('ae6ae8e5ccbfb04590405997ee2d52d2b330726137b875053c36d94e974d162f', 'hex'),
  Buffer.from('0dbbe8e4ae425a6d2687f1a7e3ba17bc98c673636790f1b8ad91193c05875ef1', 'hex'),
  // Buffer.from('c88b703fb08cbea894b6aeff5a544fb92e78a18e19814cd85da83b71f772aa6c', 'hex'),
  // Buffer.from('388c684f0ba1ef5017716adb5d21a053ea8e90277d0868337519f97bede61418', 'hex'),
  // Buffer.from('659cbb0e2411a44db63778987b1e22153c086a95eb6b18bdf89de078917abc63', 'hex'),
  // Buffer.from('82d052c865f5763aad42add438569276c00d3d88a2d062d36b2bae914d58b8c8', 'hex'),
  // Buffer.from('aa3680d5d48a8283413f7a108367c7299ca73f553735860a87b08f39395618b7', 'hex'),
  // Buffer.from('0f62d96d6675f32685bbdb8ac13cda7c23436f63efbb9d07700d8669ff12b7c4', 'hex'),
  // Buffer.from('8d5366123cb560bb606379f90a0bfd4769eecc0557f1b362dcae9012b548b1e5', 'hex')
]

EVMHandler = {
  // debuggers provided by Remix
  debugger: null,
  // virtual machine implemented by js
  vm: null,
  stateTrie: null,
  // web3 object corresponding to vm
  web3vm: null,
  // a map from address to private keys
  accounts: {},
  defaultAccount: null,
  contracts: {},
  defaultContractAddress: "",
  // currently use web3 as utils
  web3: new Web3(),
  // a nonce
  t: 12,
  defaultBalance: "ffffffffffffffffffffffffffffffff",
  startTime: new Date().getTime() / 1000 | 0,
  txCnt: 0,

  init: () => {
    return new Promise((resolve, reject) => {
      EVMHandler.accounts = {}
      EVMHandler.contracts = {}
      EVMHandler.initVM().then((vm) => {
        EVMHandler.vm = vm;
        EVMHandler.web3vm = new remixLib.vm.Web3VMProvider()
        EVMHandler.web3vm.setVM(EVMHandler.vm)
        EVMHandler.debugger = new Debugger({
          web3: EVMHandler.web3vm
        })
        EVMHandler.startTime = new Date().getTime() / 1000 | 0
        EVMHandler.txCnt = 0
        resolve();
      })
    });
  },

  initVM: () => {
    return new Promise((resolve, reject) => {
      let utileth = require('ethereumjs-util')
      let VM = require('ethereumjs-vm')
      EVMHandler.stateTrie = new Trie()
      let vm = new VM({
        state: EVMHandler.stateTrie
      })
      EVMHandler.accounts = [];
      async.eachSeries(privateKeys, (privateKey, next) => {
        let address = utileth.privateToAddress(privateKey)
        EVMHandler.accounts[utileth.bufferToHex(address).replace("0x", "")] = privateKey.toString('hex');
        if (!EVMHandler.defaultAccount) {
          EVMHandler.defaultAccount = utileth.bufferToHex(address).replace("0x", "");
        }
        next();
      }, (err) => {
        // nothing;
      })
      EVMHandler.resetBalance(EVMHandler.defaultBalance).then(() => {
        resolve(vm);
      })
    });
  },

  resetBalance: (balance) => {
    return new Promise((resolve, reject) => {
      let accList = Object.keys(EVMHandler.accounts);
      async.eachSeries(accList, (addressHex, next) => {
        // set balance for each account
        if (utileth.isHexPrefixed(addressHex)) {
          addressHex = addressHex.replace("0x", "")
        }
        let address = Buffer.from(addressHex, "hex")
        let account = new Account();
        account.balance = Buffer.from(balance, "hex")
        EVMHandler.stateTrie.put(address, account.serialize(), () => {
          next();
        })
      }, (err) => {
        // nothing;
      })
      resolve();
    });
  },

  // compile a contract source to a contract object
  compile: (source, name) => {
    let filename = "filename";
    let output = solc.compile({ 'sources': { filename: source } }, 1);
    let contract_name = filename + ":" + name;
    let contract = output.contracts[contract_name];
    return contract;
  },

  getAccounts: () => {
    return new Promise((resolve, reject) => {
      let accList = Object.keys(EVMHandler.accounts);
      let accountsWithBalance = {};
      async.eachSeries(accList, (addressHex, next) => {
        if (addressHex == EVMHandler.defaultAccount) {
          next();
          return;
        }
        if (utileth.isHexPrefixed(addressHex)) {
          addressHex = addressHex.replace("0x", "")
        }
        let address = Buffer.from(addressHex, "hex")
        EVMHandler.vm.stateManager.getAccount(address, (err, account) => {
          if (err) reject(err);
          accountsWithBalance[addressHex] = utileth.bufferToHex(account.balance);
          next();
        })
      }, (err) => {
        resolve(accountsWithBalance);
      })
    })
  },

  // deploy a new contract; take compiled contract from solc as input
  deploy: (contract) => {
    return new Promise((resolve, reject) => {
      EVMHandler.resetBalance(EVMHandler.defaultBalance).then(() => {
        EVMHandler.sendTx(EVMHandler.defaultAccount, EVMHandler.defaultContractAddress, "0", contract.bytecode).then((result) => {
          if (!result.createdAddress && (!EVMHandler.defaultContractAddress || EVMHandler.defaultContractAddress == ""))
            reject(Error("Invalid contract address"));
          if (result.createdAddress && result.createdAddress !== undefined) {
            result.address = utileth.bufferToHex(result.createdAddress);
          }
          else {
            result.address = EVMHandler.defaultContractAddress;
          }
          // EVMHandler.contracts[result.address] = contract;
          // init balance for newly deployed contracts
          let address = Buffer.from(result.address.replace("0x", ""), "hex")
          // let address = result.address.replace("0x", "")
          let account = EVMHandler.stateTrie.get(address, (err, accData) => {
            let account = new Account(accData);
            // let rand_len = Math.floor(Math.random() * 24 + 8)
            account.balance = Buffer.from(EVMHandler.defaultBalance, "hex");
            EVMHandler.stateTrie.put(address, account.serialize(), () => {
              resolve(result);
            })
          });
        }).catch((err) => {
          reject(err)
        })
      })
    })
  },

  debug: (txhash) => {
    return new Promise((resolve, reject) => {
      EVMHandler.debugger.debug(txhash);
      resolve(EVMHandler.debugger.traceManager.trace)
    });
  },

  // send a raw transaction
  sendTx: (from, to, value, data, revertCallFlag=false) => {
    if (value == "") value = "0";
    return new Promise((resolve, reject) => {
      EVMHandler.txCnt += 1;
      let opts = {
        nonce: new BN(from.nonce++),
        gasPrice: new BN(0),
        gasLimit: new BN(3000000, 10),
        from: Buffer.from(from.replace("0x", ""), 'hex'),
        to: Buffer.from(to.replace("0x", ""), 'hex'),
        value: new BN(value, 10),
        data: Buffer.from(data.replace("0x", ""), 'hex')
      }
      let tx = new Tx(opts)

      tx.sign(Buffer.from(EVMHandler.accounts[from], 'hex'));
      let block = new Block({
        header: {
          timestamp: EVMHandler.startTime + EVMHandler.txCnt * 3600 * 24 * 5,
          number: 0
        },
        transactions: [],
        uncleHeaders: []
      })
      EVMHandler.vm.runTx({block: block, tx: tx, skipBalance: false, skipNonce: true, revertCallFlag: revertCallFlag}, (error, result) => {
        if (error || result == null || result === undefined) {
          reject(error);
        }
        txHash = utileth.bufferToHex(tx.hash());
        // resolve(result)
        EVMHandler.web3vm.eth.getTransaction(txHash, (err, evmTx) => {
          evmTx.to = to;
          if (err) {
            reject(err);
          } else {
            if (result == null || result === undefined) reject(null)
            else { result.tx = evmTx; resolve(result); }
          }
        })
      })
    })
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