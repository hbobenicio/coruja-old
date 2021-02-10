# Coruja

## Dev/Build Requirements

- Python 3
- C11 Compiler (clang or gcc recommended)

## Setup

```
python -m venv venv
. venv/bin/activate

pip install -U pip
pip install -r dev-requirements.txt

mkdir build && build
```

## Installing/Building dependencies

```
cd build
conan install .. --build=openssl
```

## Build

```
cd build
cmake ..
make
```

## Test

```
./build/bin/coruja-unit-tests
```
