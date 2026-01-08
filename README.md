# Socks5 chain proxy

SOCKS5→SOCKS5 chaining proxy

implemented in C for Linux and Windows.
On Linux, the event loop is io_uring-based; on Windows, it uses Winsock2 with IOCP.

## License
MIT License. See [LICENSE](LICENSE) for details.

## Requirements
- CMake 3.15+
- A C compiler with C11 support (GCC, Clang, MSVC)
- On Linux:
  - liburing development files
- On Windows:
  - MinGW-w64 (for cross-compiling from Linux)

## Build linux (elf)

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## Build linux (exe)

```bash
cmake -S . -B build-win -G Ninja \
            -DCMAKE_SYSTEM_NAME=Windows \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc \
            -DCMAKE_RC_COMPILER=x86_64-w64-mingw32-windres

cmake --build build-win
```

## Unit tests

```bash
cmake --build build
ctest --test-dir build --output-on-failure --output-junit junit.xml
```

## Configuration
Configuration is done via a JSON file. See `conf.ini` for an example configuration.

## Usage linux
```bash
./socks5-chain-proxy --config conf.ini
```

## Usage windows
```bash
socks5-chain-proxy.exe --config conf.ini
```

## Usage windows in linux (wine)
```bash
wine socks5-chain-proxy.exe --config conf.ini
```

## Options
```
--config <file>  - Path to configuration file

or

<listen_port> [username password] - Listen on <listen_port> with optional username and password for authentication
```

## PS
This project is a personal experiment and learning exercise. Use at your own risk. In development was using AI tools to help with some parts of the code.