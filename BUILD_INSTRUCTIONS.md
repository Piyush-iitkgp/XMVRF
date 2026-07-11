# XM-VRF Build Guide

## Requirements

* CMake (3.10 or later)
* C++17 compiler
* OpenSSL

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y cmake g++ libssl-dev
```

### macOS

```bash
brew install cmake openssl
```

If OpenSSL is not detected:

```bash
cmake .. -DOPENSSL_DIR=$(brew --prefix openssl)
```

---

## Build

```bash
mkdir build
cd build
cmake ..
make -j4
```

Or, on macOS:

```bash
cmake .. -DOPENSSL_DIR=$(brew --prefix openssl)
make -j4
```

---

## Run

From the project root directory:

```bash
./build/bin/xmvrf
```

To verify that the build was successful:

```bash
./build/bin/xmvrf << 'EOF'
7
EOF
```

The program should start successfully and create the `output_files/` directory automatically.
