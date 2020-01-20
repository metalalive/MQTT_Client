# MQTT v5.0 Client implementation
[![Build Status](https://travis-ci.org/metalalive/MQTT_Client.svg?branch=master)](https://travis-ci.org/metalalive/MQTT_Client)
[![codecov.io](http://codecov.io/github/metalalive/MQTT_Client/coverage.svg?branch=master)](http://codecov.io/github/metalalive/MQTT_Client?branch=master)

### Quick build command

To build MQTT client library, you have :
```
make DEBUG=yes
```
where `DEBUG=yes` is optional for debugging purpose. You will get `build/libmqttclient.a` when everything works well.


To Build the test image, you have :
```
make tests  DEBUG=yes  PLUS_C_DEFS="MQTT_CFG_RUN_TEST_THREAD "
```
where `MQTT_CFG_RUN_TEST_THREAD` is optional macro if you'd like to run the test in seperate thread.


optional openOCD debug console (user specific) :
```
make dbg_server OPENOCD_HOME=/path/to/your/openocd_folder
```

optional GDB debug command (user specific) :
```
make  dbg_client
```






