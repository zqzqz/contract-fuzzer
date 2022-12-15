FROM ubuntu:18.04

RUN apt-get update && apt-get install -y wget git tmux build-essential software-properties-common curl \
 && add-apt-repository ppa:deadsnakes/ppa && apt-get update \
 && apt-get -y install python3 python3-dev python3-pip \
 && curl -sL https://deb.nodesource.com/setup_8.x -o nodesource_setup.sh && bash nodesource_setup.sh && apt-get -y install nodejs
COPY . /contract-fuzzer
WORKDIR /contract-fuzzer/src
RUN git config --global url.https://github.com/.insteadOf git://github.com/
RUN cd evmjs/ && npm install && cd node_modules && rm -rf ethereumjs-vm && git clone https://github.com/zqzqz/ethereumjs-vm && cd ethereumjs-vm && git checkout contract-fuzzer && cp -R lib/ dist/ && npm install ethereumjs-util@5.2.0

RUN apt-get install -y \
     autoconf \
     pkg-config \
     libtool \
     zlib1g-dev \
     libjpeg-dev

RUN cd pyfuzz/ && python3 -m pip install -r requirements.txt
RUN apt-get -y install vim \
 && curl -o /usr/bin/solc -fL https://github.com/ethereum/solidity/releases/download/v0.4.25/solc-static-linux && chmod u+x /usr/bin/solc

WORKDIR /contract-fuzzer/mythril-custom
RUN patch /usr/local/lib/python3.6/dist-packages/mythril/analysis/solver.py mythril.patch
RUN cd mythril-concolic-plugin && python3 setup.py install

WORKDIR /
RUN mkdir /root/.mythril && touch /root/.mythril/signatures.db
CMD ["/bin/bash"]
