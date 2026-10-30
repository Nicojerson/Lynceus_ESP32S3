idf_component_register(SRCS "main.c"
                       INCLUDE_DIRS "."
                       REQUIRES esp_wifi nvs_flash esp_event esp_netif lwip driver esp_driver_uart esp_timer)