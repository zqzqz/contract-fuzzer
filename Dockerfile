FROM ubuntu:16.04

RUN apt-get update && apt-get install -y wget git build-essential software-properties-common curl
RUN add-apt-repository ppa:deadsnakes/ppa && apt-get update
RUN apt-get -y install python3.6 python3.6-dev python3-pip
RUN curl -sL https://deb.nodesource.com/setup_8.x -o nodesource_setup.sh && bash nodesource_setup.sh && apt-get -y install nodejs
COPY . /contract-fuzzer
WORKDIR /contract-fuzzer/src
RUN cd evmjs/ && npm install && cd node_modules && rm -rf ethereumjs-vm && git clone https://github.com/zqzqz/ethereumjs-vm && cd ethereumjs-vm && git checkout contract-fuzzer && cp -R lib/ dist/ && npm install ethereumjs-util@5.2.0
RUN cd pyfuzz/ && python3.6 -m pip install -r requirements.txt
RUN apt-get -y install vim
RUN curl -o /usr/bin/solc -fL https://github.com/ethereum/solidity/releases/download/v0.4.25/solc-static-linux && chmod u+x /usr/bin/solc

CMD ["/bin/bash"]