# MQTT v5.0 Client implementation
[![Build Status](https://travis-ci.org/metalalive/MQTT_Client.svg?branch=master)](https://travis-ci.org/metalalive/MQTT_Client)
[![codecov.io](http://codecov.io/github/metalalive/MQTT_Client/coverage.svg?branch=master)](http://codecov.io/github/metalalive/MQTT_Client?branch=master)

### Overview

This is MQTT v5 client implementation, with limited TLS v1.3 network connection, third-party cryptography library. It's verified on different embedded system platforms (currently STM32F4 and Raspberry PI development board)

### Quick start

Download all necessary third-party repositories before building MQTT client library:
```
make  download_3party
```

To build MQTT client library, you have :
```
make  DEBUG=yes  -C third_party
make  DEBUG=yes
```
where `DEBUG=yes` is optional for debugging purpose. You will get `build/libmqttclient.a` if the library is successfully built.


To Build the demo test images, you have :
```
make demo DEBUG=yes  PLUS_C_DEFS="MQTT_CFG_RUN_TEST_THREAD "
```
where `MQTT_CFG_RUN_TEST_THREAD` is optional macro if you'd like to run the test in seperate thread.


To build / run unit tests, you have :
```
make  utest
```


optional openOCD debug console (user specific) :
```
make dbg_server OPENOCD_HOME=/path/to/your/openocd_folder
```

optional GDB debug command (user specific) :
```
make  dbg_client
```






