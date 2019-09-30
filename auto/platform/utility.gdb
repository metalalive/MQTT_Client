
define reload_image
    monitor  reset
    monitor  halt
    load
end


file     build/mqtt_client_tcp.elf
target   remote localhost:3333
reload_image
info     b


