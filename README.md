# CANISTER FUZZING

 **Work in progress**


## Build dependencies (not exhaustive)

```sh

rustup default stable
rustup target add wasm32-unknown-unknown

sudo apt update && sudo apt install \
        curl \
        git \
        gcc \
        lld \
        sudo \
        wget \
        tree \
        cmake \
        wabt \
        build-essential \
        pkg-config \
        libssl-dev \
        libunwind-dev \
        libusb-1.0-0-dev \
        libsqlite3-dev \
        zlib1g-dev \
        libclang-18-dev \
        protobuf-compiler \
        llvm \
        liblmdb-dev \
        liblzma-dev
```


## Motoko usage

* Automatically handled via build script. Uses dfx to build the canisters for now.
* Requires dfx & mops as build dependencies