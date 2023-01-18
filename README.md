

### Compile and install the dev.com debug version

```
mkdir build_dev_debug && cd build_dev_debug
cmake .. 
make
```

### Compile and install the release version of the development network

```
mkdir build_dev_release && cd build_dev_release
cmake .. -DCMAKE_BUILD_TYPE=Release
make
```

### Compile and install the testnet debug version

```
mkdir build_test_debug && cd build_test_debug
cmake .. -DTESTCHAIN=ON
make
```

### Compile and install the testnet release version

```
mkdir build_test_release && cd build_test_release
cmake .. -DTESTCHAIN=ON -DCMAKE_BUILD_TYPE=Release
make
```

### Compile and install the mainnet debug version

```
mkdir build_primary_debug && cd build_primary_debug
cmake .. -DPRIMARYCHAIN=ON 
make
```

### Compile and install the mainnet release version

```
mkdir build_primary_release && cd build_primary_release
cmake .. -DPRIMARYCHAIN=ON -DCMAKE_BUILD_TYPE=Release
make
```
