
define reload_image
    monitor  reset
    monitor  halt
    load
end


define  connect_openocd_local_server
    target   remote localhost:3333
    reload
end


#### file     build/your_test_image.elf


