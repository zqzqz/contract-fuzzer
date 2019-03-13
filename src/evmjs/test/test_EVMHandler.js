const fs = require('fs');
const path = require('path');
let evm = require("../EVMHandler");
let blockchain = require("../blockchain");

let name = "Test";
let source = fs.readFileSync(path.join(__dirname, "../../static/contracts/Test.sol"), 'utf-8');
let address = null;
let txhash = null;

evm.init()
let accs = Object.keys(evm.accounts);
let contract = evm.compile(source, name);
fs.writeFileSync("testContract.json", JSON.stringify(contract, null, 2));
// console.log(contract)
evm.deploy(contract).then((result) => {
  console.log("contract deployed:", result.tx.contractAddress);
  return evm.sendFormatTx(accs[1], result.tx.contractAddress, 0, "test1", ["0xffff"])
}).then((result) => {
  console.log("transaction accepted:", result.tx.hash);
  // console.log(result.tx, result.res)
  return evm.debug(result.tx);
}).then((trace) => {
  console.log("trace length:", trace.length);
  fs.writeFileSync("testTrace.json", JSON.stringify(trace, null, 2));
  // console.log(trace)
}).catch((err) => {
  console.log(err)
})