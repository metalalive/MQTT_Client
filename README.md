# MQTT v5.0 Client implementation
[![codecov.io](http://codecov.io/github/metalalive/MQTT_Client/coverage.svg?branch=master)](http://codecov.io/github/metalalive/MQTT_Client?branch=master)

### Overview
This is MQTT v5 client implementation, with limited support of TLS v1.3 protocol, third-party cryptography library. verified on different embedded system platforms (currently STM32F4 and Raspberry PI development board).

### Quick start
This section guides you on integrating your custom application with this MQTT client library.

#### Configure your build environment
- Clear previous build `make clean`
- Copy `mqttclient-sample.conf` to `mqttclient.conf`.
- Edit `mqttclient.conf` to specify your `middleware`, `cryptolib`, `brokeraddr`, `brokerport`, and for embedded systems, `os`, `hw_platform`, `rtos_hw_build_path`, `toolchain_basepath`, and `esp_proj_home` (if using ESP8266).
- Run `make config` to generate build files based on your configuration:
  ```bash
  make config
  ```

#### Download and build third-party libraries
- Clear previous build `make clean -C ./third_party`
- Download external dependencies:
  ```bash
  make download_3party
  ```
- Build them. For Linux:
  ```bash
  make gen_3pty_libs -C ./third_party
  ```
- For embedded systems (e.g., ESP8266_AT_parser), you might need to specify platform variables if not set in `mqttclient.conf`:
  ```bash
  make gen_3pty_libs -C ./third_party  HW_PLATFORM=<your_hw> \
      RTOS_HW_BUILD_PATH=<your_rtos_path> \
      TOOLCHAIN_BASEPATH=<your_toolchain_path>
  ```

#### Build the MQTT client library
- Build the core `libmqttclient.a`:
  ```bash
  make gen_lib APPCFG_BASEPATH=/path/to/your-app/cfg
  ```
- `APPCFG_BASEPATH` indicates the path to your application configuration, essential for embedded system build

#### Build your custom application
- Place your application's source files (e.g., `my_app.c`) in a directory (e.g., `my_apps/`).
- Use `make buildapp` to compile your application. You must specify :
  - `APP_NAME` (your executable name)
  - `APP_BASEPATH` (the directory containing your source files).
- For Linux:
  ```bash
  make demo
  ```
- For embedded systems, you *must* also provide the OS and hardware-specific variables (if not already in `mqttclient.conf`):
  ```bash
  make buildapp APP_NAME=my_app APP_BASEPATH=my_apps \
      OS=<your_os> HW_PLATFORM=<your_hw> RTOS_HW_BUILD_PATH=<your_rtos_path> \
      TOOLCHAIN_BASEPATH=<your_toolchain_path> ESP_PROJ_HOME=<your_esp_path>
  
  make demo
  ```
- The compiled application will be found in the `build/` directory.

### Documentation
Check out build helper document :
```
make help
```

### License
[MIT](./LICENSE)

