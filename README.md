
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


```
dfx build cbor_decode --check --help

```