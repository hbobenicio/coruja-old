# Coruja

## Dev/Build Requirements

- Python 3
- C11 Compiler (clang or gcc recommended)
- A modern CMake (you can use asdf-vm to get it)

## Setup

```
python -m venv venv
. venv/bin/activate

pip install -U pip
pip install -r dev-requirements.txt

mkdir build
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

After building the project, just call the test

```
./build/bin/coruja-unit-tests
```

