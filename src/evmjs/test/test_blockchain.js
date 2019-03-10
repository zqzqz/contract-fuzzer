// depracated !!

const fs = require('fs');
let blockchain = require("../blockchain");

let name = "Test";
let source = fs.readFileSync("Test.sol", 'utf-8');

blockchain.init(true).then((res) => {
  return blockchain.compile(source, name);
}).then((res) => {
  console.log("contract object:", res);
  return blockchain.deploy(res);
}).then((res) => {
  console.log("deployed address:", res);
  return blockchain.execute(res, "a", [], 100, 0);
}).then((res) => {
  console.log(res)
}).catch((err) => {
  console.error(err);
});