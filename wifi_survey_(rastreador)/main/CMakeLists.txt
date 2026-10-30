idf_component_register(
    SRCS "main(wifi_survey).c" "main.c"
    INCLUDE_DIRS "."
    REQUIRES esp_wifi nvs_flash esp_event esp_netif lwip
    PRIV_REQUIRES esp_timer
)