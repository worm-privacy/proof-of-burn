FROM rust:1.87-bullseye
RUN apt update && apt install -y curl git python3 python3-pip nlohmann-json3-dev nasm libgmp-dev
RUN pip3 install web3
RUN curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh -s -- -y
RUN git clone https://github.com/iden3/circom.git && cd circom && cargo install --path circom
WORKDIR /app
COPY . .