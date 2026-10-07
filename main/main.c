/*
 * ESP32 BLE TOTP 认证器
 * 手机通过 BLE(NUS) 增删 TOTP 密钥并获取临时验证码
 */

#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_sntp.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "nvs_flash.h"

#include "storage.h"
#include "ble_totp.h"

static const char *TAG = "main";

/* BLE 透传初始化入口（定义在 ble_totp.c） */
void ble_totp_init_and_run(void);

/* -------- 可选：Wi-Fi + SNTP 授时 --------
 * TOTP 依赖准确的 Unix 时间。ESP32 无 RTC 电池，断电后时间会丢失。
 * 这里提供 Wi-Fi + SNTP 自动对时的实现。若主人使用其他方式授时（如
 * 蓝牙从手机下发时间），可以把这一段删掉或改成自定义回调。
 */
#define WIFI_SSID      "YOUR_WIFI_SSID"
#define WIFI_PASSWORD  "YOUR_WIFI_PASSWORD"
#define ENABLE_SNTP    0

#if ENABLE_SNTP
static void sntp_sync_cb(struct timeval *tv) {
    ESP_LOGI(TAG, "SNTP synced, time=%lld", (long long)tv->tv_sec);
}

static void wifi_event_handler(void *arg, esp_event_base_t base,
                               int32_t id, void *data) {
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGW(TAG, "wifi disconnected, retrying...");
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ESP_LOGI(TAG, "got ip, starting SNTP");
        esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
        esp_sntp_setservername(0, "pool.ntp.org");
        esp_sntp_setservername(1, "ntp.aliyun.com");
        sntp_set_time_sync_notification_cb(sntp_sync_cb);
        esp_sntp_init();
        /* 设置时区为北京时间 */
        setenv("TZ", "CST-8", 1);
        tzset();
    }
}

static void wifi_init_sta(void) {
    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                        &wifi_event_handler, NULL, NULL);
    esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                        &wifi_event_handler, NULL, NULL);

    wifi_config_t wc = {0};
    strncpy((char *)wc.sta.ssid, WIFI_SSID, sizeof(wc.sta.ssid) - 1);
    strncpy((char *)wc.sta.password, WIFI_PASSWORD, sizeof(wc.sta.password) - 1);

    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_config(WIFI_IF_STA, &wc);
    esp_wifi_start();
}
#endif /* ENABLE_SNTP */

void app_main(void) {
    ESP_LOGI(TAG, "==== ESP32 TOTP Authenticator starting ====");

    /* 1. 初始化存储 */
    if (totp_store_init() != 0) {
        ESP_LOGE(TAG, "storage init failed");
        return;
    }

#if ENABLE_SNTP
    /* 2. 初始化 Wi-Fi + SNTP 对时（TOTP 需要准确时间） */
    ESP_LOGI(TAG, "starting wifi + sntp...");
    wifi_init_sta();
#endif

    /* 3. 启动 BLE 服务 */
    ESP_LOGI(TAG, "starting BLE...");
    ble_totp_init_and_run();

    /* 4. 启动串口命令通道（供 CTAP2 桥接器等本地工具使用） */
    ble_totp_start_console();

    ESP_LOGI(TAG, "ready. BLE name: %s", "ATRI-TOTP");
}
