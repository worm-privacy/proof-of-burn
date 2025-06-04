FROM ubuntu
RUN apt update && apt install curl git cmake clang clang-format ninja-build libstdc++-12-dev jq -y
RUN curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
RUN curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/master/barretenberg/bbup/install | bash
RUN /root/.nargo/bin/noirup
RUN /root/.bb/bbup -nv 1.0.0-beta.6