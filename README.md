# EthPloit
An intelligent fuzzer for efficient exploit generation against smart contracts.

## Requirements

* Node (support ES6)
* Python 3.6+
* Solidity compiler solc

## Get Started

* Install nodejs and python packages

```bash
cd src/evmjs && npm install
cd -
cd src/pyfuzz && pip install -r requirements.txt
```

And slither requires the solidity compiler `solc`. Recommend to install solc@^0.4.25  

* Run nodejs server. The grpc server host a EVM handling contracts and transactions.

```bash
cd src/evmjs
npm run start
# OR node index.js
```

* Configure the fuzzer

See `src/pyfuzz/config.py` 

* Fuzz contracts

```bash
cd src
python -m pyfuzz fuzz --datadir PATH_TO_CONTRACTS --exploit
```

Option `--exploit` indicates that the model targets on finding exploitations. Otherwise the model will find vulnerabilities with option `--vulnerability`  
Currently we support detection of 4 vulnerabilities: **TimestampDependency**, **BlockNumberDependency**, **UnhandledException** and **Reentrancy**. 

The fuzzer try various inputs to the contracts and print exploitations like:

```
INFO:pyfuzz:exploitation:
[0] payload: bea948c8, sender: f17f52151ebef6c7334fad080c5704d77216b732, value: 1112
[1] payload: 108d40f8000000000000000000000000f17f52151ebef6c7334fad080c5704d77216b732, sender: f17f52151ebef6c7334fad080c5704d77216b732, value: 1217850900015
[2] payload: bea948c8, sender: f17f52151ebef6c7334fad080c5704d77216b732, value: 2151569028138
```

* Test the fuzzer

```bash
cd src
python -m pyfuzz baseline --datadir PATH_TO_CONTRACTS --exploit --random
```

Command `baseline` executes the fuzzer repeatedly, collects software performances and writes results to a report file. `--random` option makes the fuzzer ignore neural network model and randomly select actions.  

## Components

* Node.js EVM grpc server (`evmjs`)
* EVM interface to the server (`pyfuzz.evm`)
* Management of EVM types (`pyfuzz.evm_types`)
* Fuzzer including contract interface management and vulnerability detection (`pyfuzz.fuzzer`)
* A simple DQN model implemented with tensorflow (`pyfuzz.trainer`)

## Test cases

Here we provide several typical contracts exploited by EthPloit  as examples, according to triggered vulnerabilities:
* Exposed Secret:
  * Cryptographic Checks:
    * 0x35b5abaedeed12c63e04029120fa6bb084342b4d#BLITZ_GAME.sol
    * 0xfc62a32da21052fb3086e8f68ad10a7118a98606#Who_Wants_to_Be_a_Millionaire.sol
    * 0xe37b75941d9b8e3139e16a774faa2d9fb1fc9f28#Game.sol
  * Others:
    * 0xaf531dc0b3b1151af48f3d638eeb6fe6acdfd59f#TestR.sol
* Unchecked Transfer Value:
  * Unlimited Profit
    * 0xa965fb4db32d8600edcd5cc102a43e798bc3f08f#GPUMining.sol
    * 0x0a7073207bac23865e0e3b204615364b5a9d3783#HRKD.sol
    * 0x77e4af571038e876ca322fa91977ec9cb6671931#DailyRoi.sol
  * Misused this.balance:
    * 0x8D4EB49f0eD7EE6d6E00fc76eA3E9C3898bf219D#BirthDayGift.sol
    * 0x0CE087c4bd3C0bd59B08a658834c5DeC394BdB47#MultiSend.sol
  * Others:
    * 0x14a592651ed820e704a32ca1ffd4a646265c0a92#MergeCoin.sol
* Bad Access Control:
  * 0x612f1bdbe93523b7f5036efa87493b76341726e3#HOTTO.sol
  * 0x781fb4f25d07de3f3cfe2476645e52e0c661eefc#CryptoCurrencyNetwork.sol
