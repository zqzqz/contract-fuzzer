let utileth = require('ethereumjs-util')
let VM = require('ethereumjs-vm')
const solc = require('solc');

// load a test contract
let name = "Test";
let source = fs.readFileSync(path.join(__dirname, "../../static/contracts/Test.sol"), 'utf-8');

// compile the contract to solc object "contract"
let filename = "filename";
let output = solc.compile({ 'sources': { filename: source } }, 1);
let contract_name = filename + ":" + name;
let contract = output.contracts[contract_name];

// init vm
let vm = new VM()

const private_key = Buffer.from('c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3', 'hex');
const user_address = utileth.privateToAddress(private_key)

// send a raw transaction
function send_tx(to, value, data) {
  return new Promise((resolve, reject) => {
    let tx = new Tx({
      nonce: new BN(from.nonce++),
      gasPrice: new BN(1),
      gasLimit: new BN(3000000, 10),
      from: user_address,
      to: to,
      value: new BN(parseInt(value, 10), 10),
      data: data
    })

    if (tx == null) {
      reject("cannot initialize tx");
    }

    tx.sign(private_key);
    let block = new Block({
      header: {
        timestamp: new Date().getTime() / 1000 | 0,
        number: 0
      },
      transactions: [],
      uncleHeaders: []
    })
    vm.runTx({block: block, tx: tx, skipBalance: true, skipNonce: true}, function (error, result) {
      if (error) reject(error)
      resolve(result);
    })
  });
}

function put_account_balance(address, balance) {
  return new Promise((resolve, reject) => {
    vm.putAccountBalance(address, balance, () => {
      resolve();
    })
  })
}

function get_account_balance(address) {
  return new Promise((resolve, reject) => {
    vm.getAccountBalance(address, (err, balance) => {
      resolve(err, balance);
    })
  })
}

let deploy_contract = new Promise((resolve, reject) => {
  send_tx(new Buffer(), "0", contract.bytecode).then((res) => {
    resolve(res);
  })
})


put_account_balance(user_address, new BN("ffffffffffffffff", 16)).then(() => {
  return get_account_balance(user_address);
}).then((err, balance) => {
  console.log(err, balance);
  return deploy_contract;
}).then((res) => {
  console.log(res)
})