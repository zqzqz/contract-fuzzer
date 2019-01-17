# contract-fuzzer
An intelligent fuzzer on smart contracts.

# Requirements

* Node & NPM
* Python 3.5+

# Get Started

* Install nodejs and python packages
```
cd src/nodejs && npm install
cd -
cd src/python && pip3 install -r requirements.txt
```
* Run nodej tests (EVM)
```
node src/nodejs/test/test_EVMHandler.js
```
* Run rpc tests (from python)
```
node src/nodejs/index.js &  # launch a RPC server
python3 src/python/evm.py  
```

# Components

* A rpc server leveraging EVM executions (index.js) **DONE**
* Python interfaces for evm rpc calls (evm.py) **DONE**
* Decompilation of contract bytecode (python)
* Static analysis module (python)
* Fuzzing framework (python & gRPC)
* Reinforcement learning optimizer (python, tensorflow)