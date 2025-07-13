
define reload_image
    monitor  reset
    monitor  halt
    load
end


define  connect_openocd_local_server
    target   remote localhost:3333
    reload_image
end

define  dbg_tls_session_snapshot
    echo "\n--- start of dbg_tls_session_snapshot ---\n"
    set $s = (tlsSession_t *) $arg0
    print $s->flgs
    print $s->hs_state
    echo "\n--- end of dbg_tls_session_snapshot ---\n"
end

#file  build/your_test_image.elf
#connect_openocd_local_server

show environment RTOS_HW_BUILD_PATH
# --- snapshot heap usage ---
#source $RTOS_HW_BUILD_PATH/Src/os/FreeRTOS/util.gdb
#freertos_heap4_snapshot 0x20000000 0x20000

