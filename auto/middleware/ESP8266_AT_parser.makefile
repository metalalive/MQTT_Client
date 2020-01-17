#----------------------------------
# core functions of ESP_AT_parser
#----------------------------------

MIDDLEWARE_3PARTY_DOWNLOAD_CMD =  git clone https://github.com/metalalive/ESP8266_AT_parser.git 


MIDDLEWARE_3PARTY_HOME:=third_party/ESP8266_AT_parser/

C_SOURCES +=  \
    $(MIDDLEWARE_3PARTY_HOME)Src/ESP_AT_parser/src/api/esp_misc.c    \
    $(MIDDLEWARE_3PARTY_HOME)Src/ESP_AT_parser/src/api/esp_ping.c    \
    $(MIDDLEWARE_3PARTY_HOME)Src/ESP_AT_parser/src/api/esp_sta.c     \
    $(MIDDLEWARE_3PARTY_HOME)Src/ESP_AT_parser/src/api/esp_ap.c      \
    $(MIDDLEWARE_3PARTY_HOME)Src/ESP_AT_parser/src/api/esp_conn.c    \
    $(MIDDLEWARE_3PARTY_HOME)Src/ESP_AT_parser/src/esp/esp.c         \
    $(MIDDLEWARE_3PARTY_HOME)Src/ESP_AT_parser/src/esp/esp_cmd.c     \
    $(MIDDLEWARE_3PARTY_HOME)Src/ESP_AT_parser/src/esp/esp_recv_buf.c  \
    $(MIDDLEWARE_3PARTY_HOME)Src/ESP_AT_parser/src/esp/esp_parser.c    \
    $(MIDDLEWARE_3PARTY_HOME)Src/ESP_AT_parser/src/esp/esp_pktbuf.c    \
    $(MIDDLEWARE_3PARTY_HOME)Src/ESP_AT_parser/src/esp/esp_util.c      \
    $(MIDDLEWARE_3PARTY_HOME)Src/ESP_AT_parser/src/esp/esp_thread.c 

# C includes
C_INCLUDES +=  -I$(MIDDLEWARE_3PARTY_HOME)Src/ESP_AT_parser/inc  \

#----------------------------------------------------------------------------------
# for low-level OS, we use FreeRTOS which is previously verified in ESP_AT_parser
#----------------------------------------------------------------------------------
C_SOURCES +=  \
    $(MIDDLEWARE_3PARTY_HOME)Src/FreeRTOS/Source/portable/MemMang/heap_4.c \
    $(MIDDLEWARE_3PARTY_HOME)Src/FreeRTOS/Source/portable/GCC/ARM_CM4_MPU/port.c \
    $(MIDDLEWARE_3PARTY_HOME)Src/FreeRTOS/Source/croutine.c      \
    $(MIDDLEWARE_3PARTY_HOME)Src/FreeRTOS/Source/event_groups.c  \
    $(MIDDLEWARE_3PARTY_HOME)Src/FreeRTOS/Source/list.c          \
    $(MIDDLEWARE_3PARTY_HOME)Src/FreeRTOS/Source/queue.c         \
    $(MIDDLEWARE_3PARTY_HOME)Src/FreeRTOS/Source/stream_buffer.c \
    $(MIDDLEWARE_3PARTY_HOME)Src/FreeRTOS/Source/tasks.c         \
    $(MIDDLEWARE_3PARTY_HOME)Src/FreeRTOS/Source/timers.c        \
    $(MIDDLEWARE_3PARTY_HOME)Src/ESP_AT_parser/src/system/esp_system_freertos.c


C_INCLUDES +=  \
    -I$(MIDDLEWARE_3PARTY_HOME)Src/FreeRTOS/Source/include \
    -I$(MIDDLEWARE_3PARTY_HOME)Src/FreeRTOS/Source/portable/GCC/ARM_CM4_MPU 

#-------------------------------------------------
# integration parameters for this MQTT implementation
#-------------------------------------------------
C_SOURCES += src/system/middleware/ESP_AT_parser/mqtt_sys.c

C_INCLUDES += -Iinclude/system/middleware/ESP_AT_parser 


