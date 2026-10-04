#include "totp.h"

#include <string.h>
#include <ctype.h>

#include "mbedtls/md.h"
#include "mbedtls/base64.h"

/* 查找 Base32 字符对应的 5bit 值，非法字符返回 -1 */
static int base32_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= '2' && c <= '7') return c - '2' + 26;
    return -1;
}

int totp_base32_decode(const char *in, uint8_t *out, size_t out_len) {
    if (in == NULL || out == NULL) return -1;

    uint32_t buffer = 0;
    int bits = 0;
    size_t out_pos = 0;

    for (const char *p = in; *p != '\0'; p++) {
        char c = *p;
        /* 忽略常见分隔符 */
        if (c == ' ' || c == '-' || c == '=') continue;
        int v = base32_value(c);
        if (v < 0) return -1; /* 非法字符 */

        buffer = (buffer << 5) | (uint32_t)v;
        bits += 5;

        if (bits >= 8) {
            bits -= 8;
            if (out_pos >= out_len) return -1; /* 输出空间不足 */
            out[out_pos++] = (uint8_t)((buffer >> bits) & 0xFF);
        }
    }
    return (int)out_pos;
}

int totp_generate_str(const char *key, int digits, int period,
                      uint64_t timestamp, char *out) {
    if (key == NULL || out == NULL) return -1;
    if (digits < 6 || digits > 9) return -1;
    if (period <= 0) return -1;

    uint8_t key_bytes[128];
    int key_len = totp_base32_decode(key, key_bytes, sizeof(key_bytes));
    if (key_len <= 0) return -1;

    /* 计算计数器 C = floor(T / period) */
    uint64_t counter = timestamp / (uint64_t)period;

    uint8_t msg[8];
    for (int i = 7; i >= 0; i--) {
        msg[i] = (uint8_t)(counter & 0xFF);
        counter >>= 8;
    }

    /* HMAC-SHA1 */
    uint8_t hmac[20];
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    if (md == NULL) return -1;
    if (mbedtls_md_hmac(md, key_bytes, (size_t)key_len, msg, sizeof(msg), hmac) != 0) {
        return -1;
    }

    /* 动态截断 */
    int offset = hmac[19] & 0x0F;
    uint32_t bin = ((uint32_t)(hmac[offset] & 0x7F) << 24) |
                   ((uint32_t)hmac[offset + 1] << 16) |
                   ((uint32_t)hmac[offset + 2] << 8) |
                   ((uint32_t)hmac[offset + 3]);

    /* 取模得到指定位数 */
    uint32_t modulus = 1;
    for (int i = 0; i < digits; i++) modulus *= 10;
    uint32_t otp = bin % modulus;

    /* 格式化为定长字符串 */
    for (int i = digits - 1; i >= 0; i--) {
        out[i] = (char)('0' + (otp % 10));
        otp /= 10;
    }
    out[digits] = '\0';
    return 0;
}

int totp_generate(const char *key, int digits, int period, uint64_t timestamp) {
    char out[10];
    if (totp_generate_str(key, digits, period, timestamp, out) != 0) return -1;
    int v = 0;
    for (char *p = out; *p; p++) v = v * 10 + (*p - '0');
    return v;
}

/* ---------- Steam Guard ---------- */

/* Steam 字符表（26 个，去掉易混淆字符） */
static const char STEAM_CHARS[] = "23456789BCDFGHJKMNPQRTVWXY";

int steam_generate_str(const char *shared_secret_b64, uint64_t timestamp, char *out) {
    if (!shared_secret_b64 || !out) return -1;

    /* shared_secret 是 base64 编码，先解码 */
    uint8_t key_bytes[128];
    size_t key_len = 0;
    int rc = mbedtls_base64_decode(key_bytes, sizeof(key_bytes), &key_len,
                                   (const unsigned char *)shared_secret_b64,
                                   strlen(shared_secret_b64));
    if (rc != 0 || key_len == 0) return -1;

    /* 计数器 C = floor(T / 30) */
    uint64_t counter = timestamp / 30ULL;
    uint8_t msg[8];
    for (int i = 7; i >= 0; i--) {
        msg[i] = (uint8_t)(counter & 0xFF);
        counter >>= 8;
    }

    /* HMAC-SHA1 */
    uint8_t hmac[20];
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    if (!md) return -1;
    if (mbedtls_md_hmac(md, key_bytes, key_len, msg, sizeof(msg), hmac) != 0) return -1;

    /* 动态截断 */
    int offset = hmac[19] & 0x0F;
    uint32_t bin = ((uint32_t)(hmac[offset] & 0x7F) << 24) |
                   ((uint32_t)hmac[offset + 1] << 16) |
                   ((uint32_t)hmac[offset + 2] << 8) |
                   ((uint32_t)hmac[offset + 3]);

    /* 连续取模 26，得到 5 个字符 */
    for (int i = 0; i < 5; i++) {
        out[i] = STEAM_CHARS[bin % 26];
        bin /= 26;
    }
    out[5] = '\0';
    return 0;
}

int steam_generate(const char *shared_secret_b64, uint64_t timestamp, char out[6]) {
    return steam_generate_str(shared_secret_b64, timestamp, out);
}
