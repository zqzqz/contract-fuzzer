# contract-fuzzer
An intelligent fuzzer on smart contracts.

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

* Train the model

```bash
cd src
python -m pyfuzz train --datadir PATH_TO_CONTRACTS --exploit --episode 100
```

Option `--exploit` indicates that the model targets on finding exploitations. Otherwise the model will find vulnerabilities with option `--vulnerability`  
Currently we support detection of 4 vulnerabilities: **TimestampDependency**, **BlockNumberDependency**, **UnhandledException** and **Reentrancy**.  

* Fuzz contracts

```bash
cd src
python -m pyfuzz fuzz --datadir PATH_TO_CONTRACTS --exploit
```

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