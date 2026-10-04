idf_component_register(
    SRCS
        "main.c"
        "totp.c"
        "storage.c"
        "crypto.c"
        "webauthn.c"
        "ble_totp.c"
    INCLUDE_DIRS "."
    REQUIRES
        nvs_flash
        mbedtls
        bt
        esp_timer
        esp_wifi
        esp_netif
        esp_event
)
