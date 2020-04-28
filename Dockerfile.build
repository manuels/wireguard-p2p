FROM rust:1.43

WORKDIR .

RUN apt-get update
RUN apt-get install -y apt-utils
RUN apt-get install -y libopendht-dev llvm clang
RUN apt-get clean

COPY . .
RUN cargo install --path .

CMD ["wireguard-p2p"]
