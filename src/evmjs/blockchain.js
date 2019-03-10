/*
 * Deprecated!! Ganache testrpc cannot retrieve execution traces.
 * Use EVMHandler instead to debug a contract invokation or creation.
 */

const ganache = require("ganache-cli");
const Web3 = require('web3');
const solc = require('solc');

let Blockchain = {
  web3: null,
  accounts: null,
  contracts: {},

  // initialize Blockchain.web3 object and ten full-balanced accounts
  init: (restart = false) => {
    return new Promise((resolve, reject) => {
      if (Blockchain.web3 != null && Blockchain.accounts != null && !restart) {
        resolve(Blockchain.accounts);
      }
      Blockchain.web3 = new Web3();
      let config = [];
      for (var i = 0; i < 10; i++) {
        config.push({ balance: "0xffffffffffffffffffffffffffffffff" });
      }
      Blockchain.web3.setProvider(ganache.provider(config));
      Blockchain.web3.eth.getAccounts((err, accs) => {
        if (err) reject(err);
        Blockchain.accounts = accs;
        resolve(accs);
      });
    });
  },

  // compile a contract source to a contract object
  compile: (source, name) => {
    return new Promise((resolve, reject) => {
      let filename = "filename";
      let output = solc.compile({ 'sources': { filename: source } }, 1);
      let contract_name = filename + ":" + name;
      let contract = output.contracts[contract_name];
      if (!contract) reject("Compiler Error");
      else resolve(contract);
    })
  },

  // deploy the contract through web3
  deploy: (contract, args = []) => {
    return new Promise((resolve, reject) => {
      let deployContract = new Blockchain.web3.eth.Contract(JSON.parse(contract.interface), {});
      let deployTransaction = deployContract.deploy({ data: contract.bytecode, arguments: args });

      Blockchain.web3.eth.getAccounts().then((accounts) => {
        return deployTransaction.send({ from: accounts[0], gasLimit: 6000000 });
      }).then((c) => {
        console.log("deployment success");
        Blockchain.contracts[c.options.address] = contract;
        resolve(c.options.address);
      }).catch((err) => {
        reject(err);
      });
    });
  },

  // execute one transaction to given address
  execute_raw: (address, payload, sendValue, accountId) => {
    return new Promise((resolve, reject) => {
      if (!address) reject();
      Blockchain.web3.eth.getAccounts().then((accounts) => {
        return Blockchain.web3.eth.sendTransaction({ from: accounts[accountId], to: address, data: payload, value: sendValue });
      }).then((res) => {
        resolve(res);
      }).catch((err) => {
        console.log(err)
        resolve(false);
      })
    })
  },

  execute: (address, funcName, args, sendValue, accountId) => {
    let abi = JSON.parse(Blockchain.contracts[address].interface)
    let funcAbi = null;
    for(var i in abi) {
      if (abi[i]["name"] == funcName) {
        funcAbi = abi[i];
      }
    }
    if (!funcAbi) return Error("function not found");
    let payload = Blockchain.web3.eth.abi.encodeFunctionCall(funcAbi, args);
    return Blockchain.execute_raw(address, payload, sendValue, accountId);
  }
}

module.exports = Blockchain;