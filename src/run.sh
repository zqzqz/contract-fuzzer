#!/bin/bash
DIR=$(dirname $0)

cd $DIR
source python3.6/bin/activate
nohup node evmjs/index.js 2>&1 > evm.log &
echo "evm started"
sleep 8
nohup python -m pyfuzz fuzz --exploit --vulnerability --datadir ../../tmp --timeout 300 2>&1 > fuzz.log &
echo "fuzz started"
sleep 2

while true;
do
    evm_process=$(ps -aux | grep -c "index\.js")
    if [ "$evm_process" -eq "0" ]; then
        nohup node evmjs/index.js 2>&1 > /dev/null &
        echo "evm restarted"
    fi
    sleep 0.5
done