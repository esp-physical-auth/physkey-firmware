#include "storage.h"

#include <string.h>
#include <stdio.h>

#include "nvs.h"
#include "nvs_flash.h"
#include "esp_log.h"
#include "crypto.h"

static const char *TAG = "totp_store";
static const char *NVS_NS = "totp";

/* NVS key 最长只能 15 字符，且不能含括号等符号。
 * 因此不拿账号名当 key，而用固定前缀 + 序号：e00, e01 ...
 * 账号名存在结构体内部，长度和字符都不受限。 */
static void slot_key(int idx, char *out, size_t cap) {
    snprintf(out, cap, "e%02d", idx);
}

/* 查找名字对应的槽位序号，找不到返回 -1 */
static int find_slot(nvs_handle_t h, const char *name) {
    for (int i = 0; i < TOTP_MAX_ENTRIES; i++) {
        char key[8];
        slot_key(i, key, sizeof(key));
        totp_entry_t e;
        size_t len = sizeof(e);
        if (nvs_get_blob(h, key, &e, &len) == ESP_OK && len >= sizeof(totp_entry_t)) {
            if (strcmp(e.name, name) == 0) return i;
        }
    }
    return -1;
}

/* 找一个空槽位，满返回 -1 */
static int find_free_slot(nvs_handle_t h) {
    for (int i = 0; i < TOTP_MAX_ENTRIES; i++) {
        char key[8];
        slot_key(i, key, sizeof(key));
        size_t len = 0;
        if (nvs_get_blob(h, key, NULL, &len) != ESP_OK) {
            return i; /* 不存在即空闲 */
        }
    }
    return -1;
}

int totp_store_init(void) {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "NVS init failed: %s", esp_err_to_name(err));
        return -1;
    }
    return 0;
}

int totp_store_add(const char *name, const char *secret, uint8_t digits, uint16_t period)
{
    return totp_store_add_typed(name, secret, digits, period, TOTP_TYPE_STANDARD);
}

int totp_store_add_typed(const char *name, const char *secret, uint8_t digits,
                         uint16_t period, uint8_t type) {
    if (!name || !secret) return -1;
    size_t nlen = strlen(name);
    if (nlen == 0 || nlen >= TOTP_MAX_NAME) return -1;
    if (strlen(secret) >= TOTP_MAX_SECRET) return -1;
    if (digits == 0) digits = 6;
    if (period == 0) period = 30;

    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return -1;

    /* 已存在则覆盖同一槽位，否则找空槽 */
    int slot = find_slot(h, name);
    if (slot < 0) slot = find_free_slot(h);
    if (slot < 0) {
        nvs_close(h);
        ESP_LOGE(TAG, "storage full (%d entries)", TOTP_MAX_ENTRIES);
        return -1;
    }

    totp_entry_t e = {0};
    strncpy(e.name, name, TOTP_MAX_NAME - 1);
    e.digits = digits;
    e.period = period;
    e.type = type;

    /* 密钥用 AES-256-GCM 加密后存 NVS（需已解锁）。
     * 不兼容旧明文：启动时已清空。 */
    size_t slen = strlen(secret);
    if (!esp_crypto_unlocked()) {
        nvs_close(h);
        ESP_LOGW(TAG, "store locked, cannot add");
        return -1;
    }
    {
        uint8_t encbuf[TOTP_MAX_SECRET + 32];
        int enclen = esp_crypto_encrypt((const uint8_t *)secret, slen, encbuf, sizeof(encbuf));
        if (enclen <= 0 || enclen > TOTP_MAX_SECRET) {
            nvs_close(h);
            ESP_LOGE(TAG, "encrypt failed");
            return -1;
        }
        memcpy(e.secret, encbuf, enclen);
    }

    char key[8];
    slot_key(slot, key, sizeof(key));
    esp_err_t err = nvs_set_blob(h, key, &e, sizeof(e));
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return (err == ESP_OK) ? 0 : -1;
}

int totp_store_del(const char *name) {
    if (!name) return -1;
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return -1;
    int slot = find_slot(h, name);
    if (slot < 0) { nvs_close(h); return -1; }
    char key[8];
    slot_key(slot, key, sizeof(key));
    esp_err_t err = nvs_erase_key(h, key);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return (err == ESP_OK) ? 0 : -1;
}

/* 清除全部 TOTP 条目，返回清除数量 */
int totp_store_wipe(void) {
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return -1;
    int count = 0;
    for (int i = 0; i < TOTP_MAX_ENTRIES; i++) {
        char key[8];
        slot_key(i, key, sizeof(key));
        size_t len = 0;
        if (nvs_get_blob(h, key, NULL, &len) == ESP_OK) {
            if (nvs_erase_key(h, key) == ESP_OK) count++;
        }
    }
    nvs_commit(h);
    nvs_close(h);
    return count;
}

int totp_store_get(const char *name, totp_entry_t *out) {
    if (!name || !out) return -1;
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return -1;

    int slot = find_slot(h, name);
    if (slot < 0) { nvs_close(h); return -1; }
    char key[8];
    slot_key(slot, key, sizeof(key));
    totp_entry_t e = {0};
    size_t len = sizeof(e);
    esp_err_t err = nvs_get_blob(h, key, &e, &len);
    nvs_close(h);
    if (err != ESP_OK) return -1;

    /* secret 字段总是密文，解密 */
    uint8_t plain[TOTP_MAX_SECRET];
    int plen = esp_crypto_decrypt((const uint8_t *)e.secret, strlen(e.secret), plain, sizeof(plain) - 1);
    if (plen <= 0) return -2; /* 未解锁或密码不对 */
    plain[plen] = '\0';
    memcpy(e.secret, plain, plen + 1);

    *out = e;
    return 0;
}

int totp_store_dump_all(totp_emit_fn emit) {
    if (!emit) return -1;
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return -1;
    int count = 0;
    for (int i = 0; i < TOTP_MAX_ENTRIES; i++) {
        char key[8];
        slot_key(i, key, sizeof(key));
        totp_entry_t e;
        size_t len = sizeof(e);
        if (nvs_get_blob(h, key, &e, &len) != ESP_OK || len < sizeof(totp_entry_t)) continue;
        uint8_t plain[TOTP_MAX_SECRET];
        int plen = esp_crypto_decrypt((const uint8_t *)e.secret, strlen(e.secret), plain, sizeof(plain) - 1);
        if (plen <= 0) continue; /* 无法解密则跳过 */
        plain[plen] = '\0';
        memcpy(e.secret, plain, plen + 1);
        /* 每条独立一行，用 ITEM 前缀 + '|' 分隔（抗 BLE 分片/乱码） */
        char line[256];
        snprintf(line, sizeof(line), "ITEM|%s|%s|%d|%d|%d",
                 e.name, e.secret, e.type, e.digits, e.period);
        emit(line);
        count++;
    }
    nvs_close(h);
    return count;
}

int totp_store_list(char *buf, size_t cap) {
    if (!buf || cap == 0) return -1;
    buf[0] = '\0';

    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return -1;

    int count = 0;
    size_t used = 0;
    for (int i = 0; i < TOTP_MAX_ENTRIES; i++) {
        char key[8];
        slot_key(i, key, sizeof(key));
        totp_entry_t e;
        size_t len = sizeof(e);
        if (nvs_get_blob(h, key, &e, &len) != ESP_OK || len < sizeof(totp_entry_t)) continue;
        int n = snprintf(buf + used, cap - used, "%s\n", e.name);
        if (n > 0 && (size_t)n < cap - used) used += (size_t)n;
        count++;
    }
    nvs_close(h);
    return count;
}

int totp_store_count(void) {
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return 0;
    int cnt = 0;
    for (int i = 0; i < TOTP_MAX_ENTRIES; i++) {
        char key[8];
        slot_key(i, key, sizeof(key));
        size_t len = 0;
        if (nvs_get_blob(h, key, NULL, &len) == ESP_OK) cnt++;
    }
    nvs_close(h);
    return cnt;
}

