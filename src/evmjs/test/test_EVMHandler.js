const fs = require('fs');
const path = require('path');
let evm = require("../EVMHandler");

let name = "Test";
let source = fs.readFileSync(path.join(__dirname, "../../static/contracts/Test.sol"), 'utf-8');
let address = null;
let txhash = null;

evm.init()
let accs = Object.keys(evm.accounts);
let contract = evm.compile(source, name);

// console.log(contract)
evm.deploy(contract).then((result) => {
  address = result.tx.contractAddress;
  console.log("contract deployed:", address);
  return evm.sendFormatTx(accs[1], address, 0, "test2", [])
}).then((result) => {
  console.log("transaction accepted:", result.tx.hash);
  // console.log(result.tx, result.res)
  return evm.debug(result.tx);
}).then((trace) => {
  console.log("trace length:", trace.length);
  fs.writeFileSync("testTrace.json", JSON.stringify(trace, null, 2));
  return evm.queryState(address);
}).then((state) => {
  console.log("state:", state)
}).catch((err) => {
  console.log(err)
})