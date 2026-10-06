/*
 * BLE 透传服务（Nordic UART Service / NUS 兼容）
 *
 * 手机端可用任意支持 NUS 或通用 BLE 调试的 App 连接：
 *   - nRF Connect
 *   - Serial Bluetooth Terminal
 *   - 微信小程序自写的 BLE 页面等
 *
 * 指令格式（以换行符结尾，\n 或 \r\n 均可；也可单条直接发送不加换行）：
 *   ADD <名字> <Base32密钥> [数字位数] [周期秒]   新增/覆盖
 *   DEL <名字>                                     删除
 *   LIST                                           列出全部账号
 *   GET <名字>                                     获取当前临时验证码
 *   TIME <unix时间戳>                              设置设备时间（授时）
 *   HELP                                           帮助
 *
 * 示例：
 *   ADD github JBSWY3DPEHPK3PXP
 *   GET github
 *   TIME 1758930000
 *   DEL github
 */

#include "ble_totp.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_system.h"

#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

#include "totp.h"
#include "storage.h"
#include "crypto.h"
#include "webauthn.h"

#include "mbedtls/base64.h"

/* base64 编码：返回 malloc 的字符串（调用方 free），失败返回 NULL */
static char *b64_encode(const uint8_t *data, size_t len) {
    size_t olen = 0;
    if (mbedtls_base64_encode(NULL, 0, &olen, data, len) != 0) {
        /* 第一调用算长度可能返回错误，预留足够空间 */
        olen = ((len + 2) / 3) * 4 + 1;
    }
    char *out = (char *)malloc(olen + 1);
    if (!out) return NULL;
    size_t wlen = 0;
    if (mbedtls_base64_encode((unsigned char *)out, olen, &wlen, data, len) != 0) {
        free(out);
        return NULL;
    }
    out[wlen] = '\0';
    return out;
}

/* base64 解码：返回 malloc 的字节数组，*out_len 写出长度，失败返回 NULL */
static uint8_t *b64_decode(const char *str, size_t *out_len) {
    size_t slen = strlen(str);
    size_t olen = (slen / 4 + 1) * 3;
    uint8_t *out = (uint8_t *)malloc(olen);
    if (!out) return NULL;
    size_t wlen = 0;
    if (mbedtls_base64_decode(out, olen, &wlen,
                              (const unsigned char *)str, slen) != 0) {
        free(out);
        return NULL;
    }
    *out_len = wlen;
    return out;
}

static const char *TAG = "ble_totp";

/* NUS UUID（Nordic UART Service 标准 UUID）
 * 注意：BLE_UUID128_INIT 参数为 LSB-first（低位字节在前），
 * 即完整 UUID 16 字节的反序。
 * 标准 NUS 服务 UUID: 6E400001-B5A3-F393-E0A9-E50E24DCCA9E
 */
static const ble_uuid128_t nus_svc_uuid =
    BLE_UUID128_INIT(0x9e, 0xca, 0xdc, 0x24, 0x0e, 0xe5, 0xa9, 0xe0,
                     0x93, 0xf3, 0xa3, 0xb5, 0x01, 0x00, 0x40, 0x6e);
/* RX 特征：手机写入 → 设备接收
 * 6E400002-B5A3-F393-E0A9-E50E24DCCA9E
 */
static const ble_uuid128_t nus_rx_uuid =
    BLE_UUID128_INIT(0x9e, 0xca, 0xdc, 0x24, 0x0e, 0xe5, 0xa9, 0xe0,
                     0x93, 0xf3, 0xa3, 0xb5, 0x02, 0x00, 0x40, 0x6e);
/* TX 特征：设备通知 → 手机接收
 * 6E400003-B5A3-F393-E0A9-E50E24DCCA9E
 */
static const ble_uuid128_t nus_tx_uuid =
    BLE_UUID128_INIT(0x9e, 0xca, 0xdc, 0x24, 0x0e, 0xe5, 0xa9, 0xe0,
                     0x93, 0xf3, 0xa3, 0xb5, 0x03, 0x00, 0x40, 0x6e);

static uint8_t own_addr_type;
static uint16_t tx_val_handle;
static uint16_t conn_handle = BLE_HS_CONN_HANDLE_NONE;

static char rx_buf[2048];
static size_t rx_len = 0;
static bool rx_has_len = false;
static size_t rx_expect = 0;

/* 判断是否 4 位十六进制长度前缀 */
static bool is_hex4(const char *s) {
    for (int i = 0; i < 4; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return false;
    }
    return true;
}
static unsigned strtoul_len4(const char *s) {
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        char c = s[i];
        unsigned d = (c >= '0' && c <= '9') ? (c - '0')
                   : (c >= 'a' && c <= 'f') ? (c - 'a' + 10)
                   : (c - 'A' + 10);
        v = (v << 4) | d;
    }
    return v;
}

/* ---------- 时间：RTC/系统时间（秒） ---------- */
static uint64_t now_seconds(void) {
    /* esp_timer 从开机开始，若已通过 SNTP 或外部注入系统时间则用 time() */
    time_t t = time(NULL);
    if (t > 1700000000) { /* 看起来像真实时间 */
        return (uint64_t)t;
    }
    /* 回退：开机时间（会导致验证码不对，提醒用户需要授时） */
    return (uint64_t)(esp_timer_get_time() / 1000000ULL);
}

/* ---------- 通过 TX 特征发送字符串 ---------- */
static void tx_send(const char *msg) {
    ESP_LOGI(TAG, "tx_send: conn=%d tx_handle=%d msg='%s'",
             conn_handle, tx_val_handle, msg);
    if (conn_handle == BLE_HS_CONN_HANDLE_NONE) {
        ESP_LOGW(TAG, "tx_send: no connection");
        return;
    }
    if (tx_val_handle == 0) {
        ESP_LOGW(TAG, "tx_send: tx_val_handle is 0!");
        return;
    }

    size_t len = strlen(msg);
    size_t off = 0;
    /* 分包发送，每包不超过 20 字节（保守值）。
     * ★ 每片之间加短延时：否则同一 handle 的连续 notify 会被 BLE 栈
     *   堆叠/重复投递，导致对端（网页/passless）收到重复的长响应
     *   （如证书 base64 被拼接两遍）。 */
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > 20) chunk = 20;
        struct os_mbuf *om = ble_hs_mbuf_from_flat(msg + off, chunk);
        if (!om) break;
        int rc = ble_gatts_notify_custom(conn_handle, tx_val_handle, om);
        if (rc != 0) {
            ESP_LOGW(TAG, "notify failed rc=%d", rc);
            break;
        }
        off += chunk;
        if (off < len) vTaskDelay(pdMS_TO_TICKS(8));
    }
}

/* ---------- 解析并执行一条指令 ---------- */
static bool is_all_digits(const char *s) {
    if (!s || !*s) return false;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return false;
    }
    return true;
}

static void handle_command(char *line) {
    char resp[256];
    /* 去掉尾部空白 */
    size_t l = strlen(line);
    while (l > 0 && (line[l - 1] == '\r' || line[l - 1] == '\n' ||
                     line[l - 1] == ' ' || line[l - 1] == '\t')) {
        line[--l] = '\0';
    }
    if (l == 0) return;

    /* 提取第一个词（不区分大小写） */
    char *cmd = strtok(line, " \t");
    if (!cmd) return;

    /* ---- 通行密钥闸门（Passkey Gate） ----
     * 设过密码后，敏感命令一律要求先 AUTHPASS 解锁（-> esp_crypto_unlocked()）。
     * 免锁命令（首次配置/身份/帮助）白名单放行；
     * 其余未知命令也要求已解锁，避免绕过。
     */
    static const char *kOpenCmds[] = {
        "HASPASS", "SETPASS", "AUTHPASS", "HELP", "WHOAMI",
        "GETCERT", "SETCERT", "SETCERT_DEV", "SETCERT_UCA", "AUTH", "TIME", "WIPE", NULL
    };
    bool gated = true;
    for (int i = 0; kOpenCmds[i]; i++) {
        if (strcasecmp(cmd, kOpenCmds[i]) == 0) { gated = false; break; }
    }
    if (gated && esp_pass_is_set() && !esp_crypto_unlocked()) {
        tx_send("ERR locked: send AUTHPASS <pw> first\n");
        return;
    }
    if (strcasecmp(cmd, "ADD") == 0) {
        /* 手动按空格分词，不依赖全局 strtok 状态（避免影响其他命令）。
         * 密钥可能含空格分组（如 "4DTK 3OU5 ZY3V ..."），需拼接后去空格。 */
        char *rest = cmd + strlen(cmd) + 1; /* name 开始处 */
        /* 跳过连续空白 */
        while (*rest == ' ' || *rest == '\t') rest++;
        char *name = rest;
        while (*rest && *rest != ' ' && *rest != '\t') rest++;
        if (*rest) { *rest = '\0'; rest++; }
        while (*rest == ' ' || *rest == '\t') rest++;
        if (name[0] == '\0' || rest[0] == '\0') {
            tx_send("ERR usage: ADD <name> <base32secret> [digits] [period]\n");
            return;
        }
        /* 剩余部分：空格分组的密钥，可能末尾带 digits/period（纯数字）。
         * 策略：先把所有 token 收集到数组（最多 64 个），再判断末尾参数。 */
        char *toks[64];
        int ntoks = 0;
        char *p = rest;
        while (*p && ntoks < 64) {
            while (*p == ' ' || *p == '\t') p++;
            if (!*p) break;
            toks[ntoks++] = p;
            while (*p && *p != ' ' && *p != '\t') p++;
            if (*p) *p++ = '\0'; /* 就地断开 */
        }
        uint8_t digits = 6;
        uint16_t period = 30;
        int end = ntoks; /* 密钥 token 范围 [0, end) */
        bool last_is_num = ntoks >= 1 && is_all_digits(toks[ntoks - 1]) && strlen(toks[ntoks - 1]) <= 5;
        bool prev_is_num = ntoks >= 2 && is_all_digits(toks[ntoks - 2]) && strlen(toks[ntoks - 2]) <= 5;
        if (last_is_num && prev_is_num) {
            digits = (uint8_t)atoi(toks[ntoks - 2]);
            period = (uint16_t)atoi(toks[ntoks - 1]);
            end = ntoks - 2;
        } else if (last_is_num) {
            digits = (uint8_t)atoi(toks[ntoks - 1]);
            end = ntoks - 1;
        }
        char secret[200] = {0};
        size_t slen = 0;
        for (int i = 0; i < end; i++) {
            for (char *q = toks[i]; *q; q++) {
                if (slen < sizeof(secret) - 1) secret[slen++] = *q;
            }
        }
        secret[slen] = '\0';
        if (slen == 0) {
            tx_send("ERR empty secret\n");
            return;
        }
        if (digits == 0) digits = 6;
        if (period == 0) period = 30;
        /* 名字以 "steam:" 开头则标记为 Steam 类型（密钥此时存 base64 shared_secret） */
        uint8_t type = TOTP_TYPE_STANDARD;
        char real_name[TOTP_MAX_NAME];
        strncpy(real_name, name, sizeof(real_name) - 1);
        real_name[sizeof(real_name) - 1] = '\0';
        if (strncasecmp(name, "steam:", 6) == 0) {
            type = TOTP_TYPE_STEAM;
            memmove(real_name, name + 6, strlen(name + 6) + 1);
            period = 30;
        }
        if (totp_store_add_typed(real_name, secret, digits, period, type) == 0) {
            snprintf(resp, sizeof(resp), "OK added '%s'%s (%d digits / %ds)\n",
                     real_name, type == TOTP_TYPE_STEAM ? " [steam]" : "",
                     digits, period);
        } else {
            snprintf(resp, sizeof(resp), "ERR failed to add '%s'\n", real_name);
        }
        tx_send(resp);
    } else if (strcasecmp(cmd, "DEL") == 0) {
        char *name = strtok(NULL, " \t");
        if (!name) {
            tx_send("ERR usage: DEL <name>\n");
            return;
        }
        if (totp_store_del(name) == 0) {
            snprintf(resp, sizeof(resp), "OK deleted '%s'\n", name);
        } else {
            snprintf(resp, sizeof(resp), "ERR not found '%s'\n", name);
        }
        tx_send(resp);
    } else if (strcasecmp(cmd, "LIST") == 0) {
        char list[192];
        int n = totp_store_list(list, sizeof(list));
        /* 用 ';' 分隔名字，避免跟通知分包里的换行混淆，方便手机端解析 */
        for (int i = 0; list[i]; i++) {
            if (list[i] == '\n') list[i] = ';';
        }
        snprintf(resp, sizeof(resp), "OK %d entries:\n%.200s\n", n, list);
        tx_send(resp);
    } else if (strcasecmp(cmd, "DUMP") == 0) {
        /* 导出全部条目：每行 name<TAB>secret<TAB>type<TAB>digits<TAB>period
         * 供网页生成备份 JSON。 */
        int n = totp_store_dump_all(tx_send);
        snprintf(resp, sizeof(resp), "OK dumped %d entries\n", n);
        tx_send(resp);
    } else if (strcasecmp(cmd, "GET") == 0) {
        char *name = strtok(NULL, " \t");
        if (!name) {
            tx_send("ERR usage: GET <name>\n");
            return;
        }
        totp_entry_t e;
        if (totp_store_get(name, &e) != 0) {
            snprintf(resp, sizeof(resp), "ERR not found '%s'\n", name);
            tx_send(resp);
            return;
        }
        char code[16];
        uint64_t ts = now_seconds();
        if (e.type == TOTP_TYPE_STEAM) {
            if (steam_generate_str(e.secret, ts, code) != 0) {
                tx_send("ERR invalid steam secret\n");
                return;
            }
            int remain = e.period - (int)(ts % e.period);
            snprintf(resp, sizeof(resp), "OK %s: %s (valid %ds)\n", name, code, remain);
            tx_send(resp);
            return;
        }
        if (totp_generate_str(e.secret, e.digits, e.period, ts, code) != 0) {
            tx_send("ERR invalid secret\n");
            return;
        }
        int remain = e.period - (int)(ts % e.period);
        snprintf(resp, sizeof(resp), "OK %s: %s (valid %ds)\n", name, code, remain);
        tx_send(resp);
    } else if (strcasecmp(cmd, "TIME") == 0) {
        char *ts_s = strtok(NULL, " \t");
        if (!ts_s) {
            tx_send("ERR usage: TIME <unix_timestamp>\n");
            return;
        }
        time_t ts = (time_t)strtoll(ts_s, NULL, 10);
        if (ts < 1000000000) {
            tx_send("ERR timestamp too small, need unix seconds\n");
            return;
        }
        struct timeval tv = { .tv_sec = ts, .tv_usec = 0 };
        settimeofday(&tv, NULL);
        snprintf(resp, sizeof(resp), "OK time set to %lld\n", (long long)ts);
        tx_send(resp);
    } else if (strcasecmp(cmd, "HELP") == 0) {
        tx_send("免锁: HASPASS | SETPASS <pw> | AUTHPASS <pw> | HELP | WHOAMI | "
                "GETCERT | SETCERT <b64der> | AUTH <b64nonce> | TIME <unix_ts> | WIPE\n"
                "上锁(需先AUTHPASS): ADD <name> <secret> [digits] [period] | DEL <name> | "
                "LIST | GET <name> | DUMP | RESETPASS <old> <new> | "
                "IMPORTPRIV | LISTWALLET | GETWALLETPUB | SIGNHASH | DELWALLET | WIPEWALLET | "
                "WA_REG <rp> [user] | WA_FIND <rp> [user] | WA_PUB <id> | WA_SIGN <id> <b64data> | "
                "WA_SIGNHASH <id> <b64hash32> | "
                "WA_LIST | WA_DEL <id> | WA_WEBMETA <b64webid> | WA_WEBDEL <b64webid> | "
                "WA_WEBPUB <b64webid> | WA_WEBSIGNHASH <b64webid> <b64hash32> | WA_WIPE\n");
    /* ---- 设备身份（CA 信任链） ---- */
    } else if (strcasecmp(cmd, "WHOAMI") == 0) {
        /* 返回设备公钥（未压缩点 hex）与指纹，供 CA 签名 */
        uint8_t pub[65];
        int plen = espid_get_pubkey(pub, sizeof(pub));
        if (plen <= 0) { tx_send("ERR no key\n"); return; }
        uint8_t fp[32];
        espid_get_pubkey_fingerprint(fp);
        char *b64 = b64_encode(pub, plen);
        char *b64fp = b64_encode(fp, 32);
        snprintf(resp, sizeof(resp), "OK PUBKEY:%s\nFP:%s\n",
                 b64 ? b64 : "", b64fp ? b64fp : "");
        tx_send(resp);
        if (b64) free(b64);
        if (b64fp) free(b64fp);
    } else if (strcasecmp(cmd, "GETCERT") == 0) {
        /* 返回 CA 签发的设备证书（base64）。若同时装有“用户 CA 证书”，
         * 则返回两段：“设备证书|用户CA证书”（| 分隔），供客户端链式验签。
         * 旧单 CA 模式仅返回设备证书。*/
        uint8_t cert[1024];
        int clen = espid_get_cert(cert, sizeof(cert));
        if (clen <= 0) { tx_send("ERR no cert installed\n"); return; }
        char *b64 = b64_encode(cert, clen);
        if (!b64) { tx_send("ERR encode failed\n"); return; }

        uint8_t ucacert[1024];
        int uclen = espid_get_user_ca_cert(ucacert, sizeof(ucacert));
        if (uclen > 0) {
            char *ub64 = b64_encode(ucacert, uclen);
            if (ub64) {
                /* 拼接：设备证书 | 用户CA证书 */
                size_t need = strlen(b64) + 1 + strlen(ub64) + 1;
                char *combined = (char *)malloc(need);
                if (combined) {
                    snprintf(combined, need, "%s|%s", b64, ub64);
                    /* 分两次 tx_send，避免超出单条 resp 缓冲区 */
                    char *resp2 = (char *)malloc(strlen(combined) + 16);
                    if (resp2) {
                        snprintf(resp2, strlen(combined) + 16, "OK CERT:%s\n", combined);
                        tx_send(resp2);
                        free(resp2);
                    }
                    free(combined);
                }
                free(ub64);
            } else {
                snprintf(resp, sizeof(resp), "OK CERT:%s\n", b64);
                tx_send(resp);
            }
        } else {
            snprintf(resp, sizeof(resp), "OK CERT:%s\n", b64);
            tx_send(resp);
        }
        free(b64);
    } else if (strcasecmp(cmd, "SETCERT") == 0) {
        /* 写入证书。支持两种形式：
         *   SETCERT <b64der>                  —— 仅设备证书（旧单 CA 模式）
         *   SETCERT <devb64>|<ucacertb64>     —— 设备证书 + 中间CA证书（三级链） */
        char *b64 = strtok(NULL, " \t\r\n");
        if (!b64) { tx_send("ERR usage: SETCERT <b64der>[|<ucacert_b64>]\n"); return; }

        char *pipe = strchr(b64, '|');
        char *devb64 = b64;
        char *ucab64 = NULL;
        if (pipe) { *pipe = '\0'; ucab64 = pipe + 1; }

        /* 1) 设备证书 */
        size_t dlen = 0;
        uint8_t *der = b64_decode(devb64, &dlen);
        if (!der || dlen == 0) { tx_send("ERR bad base64 (dev cert)\n"); if (der) free(der); return; }
        esp_err_t err = espid_set_cert(der, dlen);
        free(der);
        if (err != ESP_OK) { tx_send("ERR cert store failed\n"); return; }

        /* 2) 中间 CA 证书（可选） */
        if (ucab64 && ucab64[0]) {
            size_t ulen = 0;
            uint8_t *uder = b64_decode(ucab64, &ulen);
            if (!uder || ulen == 0) { tx_send("ERR bad base64 (user ca cert)\n"); if (uder) free(uder); return; }
            esp_err_t uerr = espid_set_user_ca_cert(uder, ulen);
            free(uder);
            if (uerr != ESP_OK) { tx_send("ERR user ca cert store failed\n"); return; }
            tx_send("OK cert chain installed\n");
        } else {
            tx_send("OK cert installed\n");
        }
    } else if (strcasecmp(cmd, "SETCERT_DEV") == 0) {
        /* 分帧写入：单独写设备证书（避免整条链超长）。名 SETCERT_DEV <devb64> */
        char *b64 = strtok(NULL, " \t\r\n");
        if (!b64) { tx_send("ERR usage: SETCERT_DEV <b64der>\n"); return; }
        size_t dlen = 0;
        uint8_t *der = b64_decode(b64, &dlen);
        if (!der || dlen == 0) { tx_send("ERR bad base64\n"); if (der) free(der); return; }
        esp_err_t err = espid_set_cert(der, dlen);
        free(der);
        if (err != ESP_OK) { tx_send("ERR cert store failed\n"); return; }
        tx_send("OK dev cert installed\n");
    } else if (strcasecmp(cmd, "SETCERT_UCA") == 0) {
        /* 分帧写入：单独写中间 CA 证书。名 SETCERT_UCA <ucab64> */
        char *b64 = strtok(NULL, " \t\r\n");
        if (!b64) { tx_send("ERR usage: SETCERT_UCA <b64der>\n"); return; }
        size_t ulen = 0;
        uint8_t *uder = b64_decode(b64, &ulen);
        if (!uder || ulen == 0) { tx_send("ERR bad base64\n"); if (uder) free(uder); return; }
        esp_err_t uerr = espid_set_user_ca_cert(uder, ulen);
        free(uder);
        if (uerr != ESP_OK) { tx_send("ERR user ca cert store failed\n"); return; }
        tx_send("OK uca cert installed\n");
    } else if (strcasecmp(cmd, "AUTH") == 0) {
        /* 挑战-响应：对网页给的随机数用设备私钥签名 */
        char *b64 = strtok(NULL, " \t\r\n");
        if (!b64) { tx_send("ERR usage: AUTH <b64nonce>\n"); return; }
        size_t nlen = 0;
        uint8_t *nonce = b64_decode(b64, &nlen);
        if (!nonce || nlen == 0) { tx_send("ERR bad base64\n"); if (nonce) free(nonce); return; }
        uint8_t sig[64 + 16];
        int slen = espid_sign(nonce, nlen, sig, sizeof(sig));
        free(nonce);
        if (slen <= 0) { tx_send("ERR sign failed\n"); return; }
        char *b64sig = b64_encode(sig, slen);
        snprintf(resp, sizeof(resp), "OK SIG:%s\n", b64sig ? b64sig : "");
        tx_send(resp);
        if (b64sig) free(b64sig);
    /* ---- 密码 / 特权 ---- */
    } else if (strcasecmp(cmd, "HASPASS") == 0) {
        tx_send(esp_pass_is_set() ? "OK pass set\n" : "OK no pass\n");
    } else if (strcasecmp(cmd, "SETPASS") == 0) {
        char *pw = strtok(NULL, " \t\r\n");
        if (!pw) { tx_send("ERR usage: SETPASS <pw>\n"); return; }
        if (esp_pass_is_set()) { tx_send("ERR password already set, use AUTHPASS\n"); return; }
        if (esp_pass_set(pw) == ESP_OK) {
            esp_crypto_unlock(pw); /* 设密码后立即派生并缓存主密钥 */
            tx_send("OK pass set\n");
        } else {
            tx_send("ERR pass too short\n");
        }
    } else if (strcasecmp(cmd, "AUTHPASS") == 0) {
        char *pw = strtok(NULL, " \t\r\n");
        if (!pw) { tx_send("ERR usage: AUTHPASS <pw>\n"); return; }
        if (esp_crypto_unlock(pw) == 0) {
            tx_send("OK auth ok\n");
        } else {
            tx_send("ERR wrong password\n");
        }
    /* ---- 冷钱包私钥（secp256k1，只进不出） ---- */
    } else if (strcasecmp(cmd, "IMPORTPRIV") == 0) {
        /* IMPORTPRIV <label> <priv_hex32>  —— 私钥只能进来，无法导出 */
        char *label = strtok(NULL, " \t\r\n");
        char *hex = strtok(NULL, " \t\r\n");
        if (!label || !hex) { tx_send("ERR usage: IMPORTPRIV <label> <64hex>\n"); return; }
        if (strlen(hex) != 64) { tx_send("ERR private key must be 64 hex chars\n"); return; }
        uint8_t priv[32];
        for (int i = 0; i < 32; i++) {
            char b[3] = { hex[i*2], hex[i*2+1], 0 };
            char *end;
            long v = strtol(b, &end, 16);
            if (*end) { tx_send("ERR bad hex\n"); return; }
            priv[i] = (uint8_t)v;
        }
        esp_err_t e = wallet_import(label, priv);
        memset(priv, 0, sizeof(priv));
        if (e == ESP_OK) tx_send("OK priv imported (non-exportable)\n");
        else if (!esp_crypto_unlocked()) tx_send("ERR locked, AUTHPASS first\n");
        else tx_send("ERR import failed\n");
    } else if (strcasecmp(cmd, "LISTWALLET") == 0) {
        char buf[256];
        int n = wallet_list(buf, sizeof(buf));
        if (n < 0) { tx_send("ERR locked\n"); return; }
        snprintf(resp, sizeof(resp), "OK %d keys:\n%.180s\n", n, buf);
        tx_send(resp);
    } else if (strcasecmp(cmd, "GETWALLETPUB") == 0) {
        char *label = strtok(NULL, " \t\r\n");
        if (!label) { tx_send("ERR usage: GETWALLETPUB <label>\n"); return; }
        uint8_t pub[33];
        int pl = wallet_get_pubkey(label, pub, sizeof(pub));
        if (pl <= 0) { tx_send("ERR not found or locked\n"); return; }
        char *b64 = b64_encode(pub, pl);
        snprintf(resp, sizeof(resp), "OK PUBKEY:%s\n", b64 ? b64 : "");
        tx_send(resp);
        if (b64) free(b64);
    } else if (strcasecmp(cmd, "SIGNHASH") == 0) {
        /* SIGNHASH <label> <32byte_hash_b64> —— 返回 64 字节 raw 签名 base64 */
        char *label = strtok(NULL, " \t\r\n");
        char *hb64 = strtok(NULL, " \t\r\n");
        if (!label || !hb64) { tx_send("ERR usage: SIGNHASH <label> <b64hash>\n"); return; }
        size_t hlen = 0;
        uint8_t *hash = b64_decode(hb64, &hlen);
        if (!hash || hlen != 32) { tx_send("ERR hash must be 32 bytes\n"); if (hash) free(hash); return; }
        uint8_t sig[64];
        int sl = wallet_sign_hash(label, hash, sig, sizeof(sig));
        free(hash);
        if (sl != 64) { tx_send("ERR sign failed or locked\n"); return; }
        char *b64sig = b64_encode(sig, sl);
        snprintf(resp, sizeof(resp), "OK SIG:%s\n", b64sig ? b64sig : "");
        tx_send(resp);
        memset(sig, 0, sizeof(sig));
        if (b64sig) free(b64sig);
    } else if (strcasecmp(cmd, "DELWALLET") == 0) {
        char *label = strtok(NULL, " \t\r\n");
        if (!label) { tx_send("ERR usage: DELWALLET <label>\n"); return; }
        tx_send(wallet_del(label) == 0 ? "OK deleted\n" : "ERR not found\n");
    } else if (strcasecmp(cmd, "WIPEWALLET") == 0) {
        int n = wallet_wipe();
        snprintf(resp, sizeof(resp), "OK wiped %d keys\n", n);
        tx_send(resp);
    } else if (strcasecmp(cmd, "RESETPASS") == 0) {
        /* 改密码：需先 AUTHPASS 通过；这里简化用 RESETPASS <旧> <新> */
        char *oldp = strtok(NULL, " \t\r\n");
        char *newp = strtok(NULL, " \t\r\n");
        if (!oldp || !newp) { tx_send("ERR usage: RESETPASS <old> <new>\n"); return; }
        if (!esp_pass_verify(oldp)) { tx_send("ERR wrong password\n"); return; }
        /* 密码变了，主密钥也变，已有密文将无法解 —— 提示需要重导。
         * 这里仅重置密码；旧密文保留（无法解密）。 */
        if (esp_pass_reset(newp) == ESP_OK) {
            esp_crypto_lock();
            esp_crypto_unlock(newp);
            tx_send("OK pass reset (旧加密数据需重新导入)\n");
        } else {
            tx_send("ERR pass too short\n");
        }
    } else if (strcasecmp(cmd, "WIPE") == 0) {
        /* 清除全部 TOTP：故意免锁（忘记密码时的救命手段）。
         * 只清 TOTP 数据，不影响已设密码与钱包私钥。 */
        int n = totp_store_wipe();
        snprintf(resp, sizeof(resp), "OK wiped %d entries\n", n);
        tx_send(resp);
    /* ---- 网络凭证（WebAuthn-like 硬件认证器） ---- */
    } else if (strcasecmp(cmd, "WA_REG") == 0) {
        /* WA_REG <rp> [user] —— 注册一把新凭证，返回凭证 ID(hex) 与公钥(b64) */
        char *rp = strtok(NULL, " \t\r\n");
        char *user = strtok(NULL, " \t\r\n");
        if (!rp) { tx_send("ERR usage: WA_REG <rp> [user]\n"); return; }
        uint8_t id[WA_ID_LEN];
        if (wa_register(rp, user ? user : "", id) != 0) {
            tx_send("ERR register failed (locked or full?)\n");
            return;
        }
        uint8_t pub[65];
        int pl = wa_get_pubkey(id, pub, sizeof(pub));
        char hex[WA_ID_LEN * 2 + 1];
        for (int j = 0; j < WA_ID_LEN; j++) sprintf(hex + j * 2, "%02x", id[j]);
        hex[WA_ID_LEN * 2] = 0;
        char *b64pub = (pl == 65) ? b64_encode(pub, 65) : NULL;
        snprintf(resp, sizeof(resp), "OK CRED:%s\nPUBKEY:%s\n",
                 hex, b64pub ? b64pub : "");
        tx_send(resp);
        if (b64pub) free(b64pub);
    } else if (strcasecmp(cmd, "WA_FIND") == 0) {
        /* WA_FIND <rp> [user] —— 查已有凭证 */
        char *rp = strtok(NULL, " \t\r\n");
        char *user = strtok(NULL, " \t\r\n");
        if (!rp) { tx_send("ERR usage: WA_FIND <rp> [user]\n"); return; }
        uint8_t id[WA_ID_LEN];
        if (wa_find_credential(rp, user ? user : "", id) != 0) {
            tx_send("OK NOTFOUND\n");
            return;
        }
        char hex[WA_ID_LEN * 2 + 1];
        for (int j = 0; j < WA_ID_LEN; j++) sprintf(hex + j * 2, "%02x", id[j]);
        hex[WA_ID_LEN * 2] = 0;
        snprintf(resp, sizeof(resp), "OK CRED:%s\n", hex);
        tx_send(resp);
    } else if (strcasecmp(cmd, "WA_WEBMETA") == 0) {
        /* WA_WEBMETA <b64webid> — 按对外 web credential id 返回完整元数据 + rp/user */
        char *wb64 = strtok(NULL, " \t\r\n");
        if (!wb64) { tx_send("ERR usage: WA_WEBMETA <b64webid>\n"); return; }
        size_t wlen = 0; uint8_t *webid = b64_decode(wb64, &wlen);
        if (!webid || wlen == 0) { tx_send("ERR bad webid b64\n"); if (webid) free(webid); return; }
        char rp[WA_MAX_RP], user[WA_MAX_USER];
        wa_meta_t m;
        int rc = wa_get_meta_by_webid(webid, wlen, rp, sizeof(rp), user, sizeof(user), &m);
        free(webid);
        if (rc != 0) { tx_send("ERR not found or locked\n"); return; }
        char *uid_b64 = m.user_id_len ? b64_encode(m.user_id, m.user_id_len) : NULL;
        char *dis_b64 = m.user_display_len ? b64_encode(m.user_display, m.user_display_len) : NULL;
        snprintf(resp, sizeof(resp),
                 "OK META\nrp=%s\nuser=%s\ncreated=%lld\nsign_count=%u\nalg=%d\n"
                 "cred_protect=%u\ndiscoverable=%u\nbackup_state=%u\n"
                 "user_id=%s\nuser_display=%s\n",
                 rp, user, (long long)m.created, (unsigned)m.sign_count, (int)m.alg,
                 m.cred_protect, m.discoverable, m.backup_state,
                 uid_b64 ? uid_b64 : "", dis_b64 ? dis_b64 : "");
        tx_send(resp);
        if (uid_b64) free(uid_b64);
        if (dis_b64) free(dis_b64);
    } else if (strcasecmp(cmd, "WA_META") == 0) {
        /* WA_META <id> — 返回凭证完整元数据（key=value 分行）*/
        char *hex = strtok(NULL, " \t\r\n");
        if (!hex || strlen(hex) != WA_ID_LEN * 2) { tx_send("ERR usage: WA_META <32hex>\n"); return; }
        uint8_t id[WA_ID_LEN];
        for (int j = 0; j < WA_ID_LEN; j++) {
            char b[3] = { hex[j*2], hex[j*2+1], 0 };
            id[j] = (uint8_t)strtol(b, NULL, 16);
        }
        wa_meta_t m;
        if (wa_get_meta_full(id, &m) != 0) { tx_send("ERR not found or locked\n"); return; }
        char *uid_b64 = m.user_id_len ? b64_encode(m.user_id, m.user_id_len) : NULL;
        char *dis_b64 = m.user_display_len ? b64_encode(m.user_display, m.user_display_len) : NULL;
        snprintf(resp, sizeof(resp),
                 "OK META\ncreated=%lld\nsign_count=%u\nalg=%d\ncred_protect=%u\n"
                 "discoverable=%u\nbackup_state=%u\nuser_id=%s\nuser_display=%s\n",
                 (long long)m.created, (unsigned)m.sign_count, (int)m.alg,
                 m.cred_protect, m.discoverable, m.backup_state,
                 uid_b64 ? uid_b64 : "", dis_b64 ? dis_b64 : "");
        tx_send(resp);
        if (uid_b64) free(uid_b64);
        if (dis_b64) free(dis_b64);
    } else if (strcasecmp(cmd, "WA_SETMETA") == 0) {
        /* WA_SETMETA <id> [created=<n>] [sign_count=<n>] [alg=<n>]
         *   [cred_protect=<n>] [discoverable=<0|1>] [backup_state=<n>]
         *   [user_id=<b64>] [user_display=<b64>]
         * 未提供的字段保持原值不变。*/
        char *hex = strtok(NULL, " \t\r\n");
        if (!hex || strlen(hex) != WA_ID_LEN * 2) { tx_send("ERR usage: WA_SETMETA <32hex> [k=v ...]\n"); return; }
        uint8_t id[WA_ID_LEN];
        for (int j = 0; j < WA_ID_LEN; j++) {
            char b[3] = { hex[j*2], hex[j*2+1], 0 };
            id[j] = (uint8_t)strtol(b, NULL, 16);
        }
        wa_meta_t m;
        if (wa_get_meta_full(id, &m) != 0) { tx_send("ERR not found or locked\n"); return; }
        char rp_override[WA_MAX_RP]; rp_override[0] = 0;
        char user_override[WA_MAX_USER]; user_override[0] = 0;
        bool rp_override_valid = false, user_override_valid = false;
        char *kv;
        while ((kv = strtok(NULL, " \t\r\n")) != NULL) {
            char *eq = strchr(kv, '=');
            if (!eq) continue;
            *eq = 0;
            const char *key = kv;
            const char *val = eq + 1;
            if (strcmp(key, "created") == 0)        m.created = strtoll(val, NULL, 10);
            else if (strcmp(key, "sign_count") == 0) m.sign_count = (uint32_t)strtoul(val, NULL, 10);
            else if (strcmp(key, "alg") == 0)      m.alg = (int32_t)strtol(val, NULL, 10);
            else if (strcmp(key, "cred_protect") == 0) m.cred_protect = (uint8_t)strtoul(val, NULL, 10);
            else if (strcmp(key, "discoverable") == 0) m.discoverable = (uint8_t)strtoul(val, NULL, 10);
            else if (strcmp(key, "backup_state") == 0) m.backup_state = (uint8_t)strtoul(val, NULL, 10);
            else if (strcmp(key, "user_id") == 0) {
                size_t dl = 0; uint8_t *d = val[0] ? b64_decode(val, &dl) : NULL;
                if (d) { m.user_id_len = dl > WA_MAX_UID ? WA_MAX_UID : (uint8_t)dl;
                         memcpy(m.user_id, d, m.user_id_len); free(d); }
            } else if (strcmp(key, "user_display") == 0) {
                size_t dl = 0; uint8_t *d = val[0] ? b64_decode(val, &dl) : NULL;
                if (d) { m.user_display_len = dl > WA_MAX_DISPLAY ? WA_MAX_DISPLAY : (uint8_t)dl;
                         memcpy(m.user_display, d, m.user_display_len); free(d); }
            } else if (strcmp(key, "webid") == 0) {
                size_t dl = 0; uint8_t *d = val[0] ? b64_decode(val, &dl) : NULL;
                if (d) { m.web_id_len = dl > WA_MAX_WEBID ? WA_MAX_WEBID : (uint8_t)dl;
                         memcpy(m.web_id, d, m.web_id_len); free(d); }
            } else if (strcmp(key, "rp") == 0) {
                /* b64 编码的真实 RP id，覆盖 WA_REG 时的占位值 */
                rp_override_valid = true;
                size_t dl = 0; uint8_t *d = val[0] ? b64_decode(val, &dl) : NULL;
                if (d) {
                    size_t n = dl > WA_MAX_RP - 1 ? WA_MAX_RP - 1 : dl;
                    memcpy(rp_override, d, n); rp_override[n] = 0; free(d);
                }
            } else if (strcmp(key, "user") == 0) {
                /* b64 编码的真实用户名，覆盖 WA_REG 时的占位值 */
                user_override_valid = true;
                size_t dl = 0; uint8_t *d = val[0] ? b64_decode(val, &dl) : NULL;
                if (d) {
                    size_t n = dl > WA_MAX_USER - 1 ? WA_MAX_USER - 1 : dl;
                    memcpy(user_override, d, n); user_override[n] = 0; free(d);
                }
            }
        }
        if (wa_set_meta(id, &m) != 0) { tx_send("ERR setmeta failed\n"); return; }
        if (rp_override_valid || user_override_valid) {
            if (wa_update_rp_user(id, rp_override_valid ? rp_override : NULL,
                                  user_override_valid ? user_override : NULL) != 0) {
                tx_send("ERR update rp/user failed\n"); return;
            }
        }
        tx_send("OK meta updated\n");
    } else if (strcasecmp(cmd, "WA_SETMETA_WEB") == 0) {
        /* WA_SETMETA_WEB <b64webid> [k=v ...]
         * 与 WA_SETMETA 相同，但用【对外 web credential id】定位槽位
         * （用于从 storage 读回后再写元数据的路径）。*/
        char *wb64 = strtok(NULL, " \t\r\n");
        if (!wb64) { tx_send("ERR usage: WA_SETMETA_WEB <b64webid> [k=v ...]\n"); return; }
        size_t wlen = 0; uint8_t *webid = b64_decode(wb64, &wlen);
        if (!webid || wlen == 0) { tx_send("ERR bad webid b64\n"); if (webid) free(webid); return; }
        uint8_t id[WA_ID_LEN];
        wa_meta_t m;
        int rc = wa_get_id_meta_by_webid(webid, wlen, id, &m);
        free(webid);
        if (rc != 0) { tx_send("ERR not found or locked\n"); return; }
        char rp_override[WA_MAX_RP]; rp_override[0] = 0;
        char user_override[WA_MAX_USER]; user_override[0] = 0;
        bool rp_override_valid = false, user_override_valid = false;
        char *kv;
        while ((kv = strtok(NULL, " \t\r\n")) != NULL) {
            char *eq = strchr(kv, '=');
            if (!eq) continue;
            *eq = 0;
            const char *key = kv;
            const char *val = eq + 1;
            if (strcmp(key, "created") == 0)        m.created = strtoll(val, NULL, 10);
            else if (strcmp(key, "sign_count") == 0) m.sign_count = (uint32_t)strtoul(val, NULL, 10);
            else if (strcmp(key, "alg") == 0)      m.alg = (int32_t)strtol(val, NULL, 10);
            else if (strcmp(key, "cred_protect") == 0) m.cred_protect = (uint8_t)strtoul(val, NULL, 10);
            else if (strcmp(key, "discoverable") == 0) m.discoverable = (uint8_t)strtoul(val, NULL, 10);
            else if (strcmp(key, "backup_state") == 0) m.backup_state = (uint8_t)strtoul(val, NULL, 10);
            else if (strcmp(key, "user_id") == 0) {
                size_t dl = 0; uint8_t *d = val[0] ? b64_decode(val, &dl) : NULL;
                if (d) { m.user_id_len = dl > WA_MAX_UID ? WA_MAX_UID : (uint8_t)dl;
                         memcpy(m.user_id, d, m.user_id_len); free(d); }
            } else if (strcmp(key, "user_display") == 0) {
                size_t dl = 0; uint8_t *d = val[0] ? b64_decode(val, &dl) : NULL;
                if (d) { m.user_display_len = dl > WA_MAX_DISPLAY ? WA_MAX_DISPLAY : (uint8_t)dl;
                         memcpy(m.user_display, d, m.user_display_len); free(d); }
            } else if (strcmp(key, "rp") == 0) {
                rp_override_valid = true;
                size_t dl = 0; uint8_t *d = val[0] ? b64_decode(val, &dl) : NULL;
                if (d) { size_t n = dl > WA_MAX_RP - 1 ? WA_MAX_RP - 1 : dl;
                         memcpy(rp_override, d, n); rp_override[n] = 0; free(d); }
            } else if (strcmp(key, "user") == 0) {
                user_override_valid = true;
                size_t dl = 0; uint8_t *d = val[0] ? b64_decode(val, &dl) : NULL;
                if (d) { size_t n = dl > WA_MAX_USER - 1 ? WA_MAX_USER - 1 : dl;
                         memcpy(user_override, d, n); user_override[n] = 0; free(d); }
            }
        }
        if (wa_set_meta(id, &m) != 0) { tx_send("ERR setmeta failed\n"); return; }
        if (rp_override_valid || user_override_valid) {
            if (wa_update_rp_user(id, rp_override_valid ? rp_override : NULL,
                                  user_override_valid ? user_override : NULL) != 0) {
                tx_send("ERR update rp/user failed\n"); return;
            }
        }
        tx_send("OK meta updated\n");
    } else if (strcasecmp(cmd, "WA_PUB") == 0) {
        /* WA_PUB <cred_hex> —— 取凭证公钥（未压缩点 65B, b64） */
        char *hex = strtok(NULL, " \t\r\n");
        if (!hex || strlen(hex) != WA_ID_LEN * 2) { tx_send("ERR usage: WA_PUB <32hex>\n"); return; }
        uint8_t id[WA_ID_LEN];
        for (int j = 0; j < WA_ID_LEN; j++) {
            char b[3] = { hex[j*2], hex[j*2+1], 0 };
            id[j] = (uint8_t)strtol(b, NULL, 16);
        }
        uint8_t pub[65];
        int pl = wa_get_pubkey(id, pub, sizeof(pub));
        if (pl != 65) { ESP_LOGW(TAG, "WA_PUB fail: wa_get_pubkey id=%.*s -> %d", WA_ID_LEN*2, hex, pl); tx_send("ERR not found or locked\n"); return; }
        char *b64 = b64_encode(pub, 65);
        snprintf(resp, sizeof(resp), "OK PUBKEY:%s\n", b64 ? b64 : "");
        tx_send(resp);
        if (b64) free(b64);
    } else if (strcasecmp(cmd, "WA_SIGN") == 0) {
        /* WA_SIGN <cred_hex> <b64data> —— 认证：用凭证私钥对 data 签名，返回 64B raw(r||s) b64 */
        char *hex = strtok(NULL, " \t\r\n");
        char *db64 = strtok(NULL, " \t\r\n");
        if (!hex || !db64) { tx_send("ERR usage: WA_SIGN <32hex> <b64data>\n"); return; }
        if (strlen(hex) != WA_ID_LEN * 2) { tx_send("ERR bad cred id\n"); return; }
        uint8_t id[WA_ID_LEN];
        for (int j = 0; j < WA_ID_LEN; j++) {
            char b[3] = { hex[j*2], hex[j*2+1], 0 };
            id[j] = (uint8_t)strtol(b, NULL, 16);
        }
        size_t dlen = 0;
        uint8_t *data = b64_decode(db64, &dlen);
        if (!data || dlen == 0) { tx_send("ERR bad base64\n"); if (data) free(data); return; }
        uint8_t sig[64];
        int sl = wa_sign(id, data, dlen, sig, sizeof(sig));
        free(data);
        if (sl != 64) { tx_send("ERR sign failed (locked or not found?)\n"); return; }
        char *b64sig = b64_encode(sig, 64);
        snprintf(resp, sizeof(resp), "OK SIG:%s\n", b64sig ? b64sig : "");
        tx_send(resp);
        memset(sig, 0, sizeof(sig));
        if (b64sig) free(b64sig);
    } else if (strcasecmp(cmd, "WA_SIGNHASH") == 0) {
        /* WA_SIGNHASH <cred_hex> <b64hash32> —— 对已算好的 32B SHA-256 摘要直接签名
         * 供 CTAP2/WebAuthn 桥使用（PC 端已算好 authenticatorData||clientDataHash 的摘要）。
         * 返回 64B raw(r||s) b64。 */
        char *hex = strtok(NULL, " \t\r\n");
        char *hb64 = strtok(NULL, " \t\r\n");
        if (!hex || !hb64) { tx_send("ERR usage: WA_SIGNHASH <32hex> <b64hash32>\n"); return; }
        if (strlen(hex) != WA_ID_LEN * 2) { tx_send("ERR bad cred id\n"); return; }
        uint8_t id[WA_ID_LEN];
        for (int j = 0; j < WA_ID_LEN; j++) {
            char b[3] = { hex[j*2], hex[j*2+1], 0 };
            id[j] = (uint8_t)strtol(b, NULL, 16);
        }
        size_t hlen = 0;
        uint8_t *hash = b64_decode(hb64, &hlen);
        if (!hash || hlen != 32) { tx_send("ERR hash must be 32 bytes\n"); if (hash) free(hash); return; }
        uint8_t sig[64];
        int sl = wa_sign_hash(id, hash, sig, sizeof(sig));
        free(hash);
        if (sl != 64) { tx_send("ERR sign failed (locked or not found?)\n"); return; }
        char *b64sig = b64_encode(sig, 64);
        snprintf(resp, sizeof(resp), "OK SIG:%s\n", b64sig ? b64sig : "");
        tx_send(resp);
        memset(sig, 0, sizeof(sig));
        if (b64sig) free(b64sig);
    } else if (strcasecmp(cmd, "WA_LIST") == 0) {
        /* WA_LIST —— 列出全部凭证，每行 id<TAB>rp<TAB>user */
        int n = wa_list(tx_send);
        snprintf(resp, sizeof(resp), "OK %d credentials\n", n < 0 ? 0 : n);
        tx_send(resp);
    } else if (strcasecmp(cmd, "WA_DEL") == 0) {
        char *hex = strtok(NULL, " \t\r\n");
        if (!hex || strlen(hex) != WA_ID_LEN * 2) { tx_send("ERR usage: WA_DEL <32hex>\n"); return; }
        uint8_t id[WA_ID_LEN];
        for (int j = 0; j < WA_ID_LEN; j++) {
            char b[3] = { hex[j*2], hex[j*2+1], 0 };
            id[j] = (uint8_t)strtol(b, NULL, 16);
        }
        tx_send(wa_delete(id) == 0 ? "OK deleted\n" : "ERR not found\n");
    } else if (strcasecmp(cmd, "WA_WEBDEL") == 0) {
        /* WA_WEBDEL <b64webid> —— 按对外 web credential id 删除（passless 用）*/
        char *wb64 = strtok(NULL, " \t\r\n");
        if (!wb64) { tx_send("ERR usage: WA_WEBDEL <b64webid>\n"); return; }
        size_t wlen = 0; uint8_t *webid = b64_decode(wb64, &wlen);
        if (!webid || wlen == 0) { tx_send("ERR bad webid b64\n"); if (webid) free(webid); return; }
        int rc = wa_delete_by_webid(webid, wlen);
        free(webid);
        tx_send(rc == 0 ? "OK deleted\n" : "ERR not found\n");
    } else if (strcasecmp(cmd, "WA_WEBPUB") == 0) {
        /* WA_WEBPUB <b64webid> —— 按 web credential id 取公钥（未压缩点 65B, b64）*/
        char *wb64 = strtok(NULL, " \t\r\n");
        if (!wb64) { tx_send("ERR usage: WA_WEBPUB <b64webid>\n"); return; }
        size_t wlen = 0; uint8_t *webid = b64_decode(wb64, &wlen);
        if (!webid || wlen == 0) { tx_send("ERR bad webid b64\n"); if (webid) free(webid); return; }
        uint8_t pub[65];
        int pl = wa_get_pubkey_by_webid(webid, wlen, pub, sizeof(pub));
        free(webid);
        if (pl != 65) { tx_send("ERR not found or locked\n"); return; }
        char *b64 = b64_encode(pub, 65);
        snprintf(resp, sizeof(resp), "OK PUBKEY:%s\n", b64 ? b64 : "");
        tx_send(resp);
        if (b64) free(b64);
    } else if (strcasecmp(cmd, "WA_WEBSIGNHASH") == 0) {
        /* WA_WEBSIGNHASH <b64webid> <b64hash32> —— 按 web credential id 指纹签名 */
        char *wb64 = strtok(NULL, " \t\r\n");
        char *hb64 = strtok(NULL, " \t\r\n");
        if (!wb64 || !hb64) { tx_send("ERR usage: WA_WEBSIGNHASH <b64webid> <b64hash32>\n"); return; }
        size_t wlen = 0; uint8_t *webid = b64_decode(wb64, &wlen);
        if (!webid || wlen == 0) { tx_send("ERR bad webid b64\n"); if (webid) free(webid); return; }
        size_t hlen = 0; uint8_t *hash = b64_decode(hb64, &hlen);
        if (!hash || hlen != 32) { tx_send("ERR hash must be 32 bytes\n"); free(webid); if (hash) free(hash); return; }
        uint8_t sig[64];
        int sl = wa_sign_hash_by_webid(webid, wlen, hash, sig, sizeof(sig));
        free(webid); free(hash);
        if (sl != 64) { tx_send("ERR sign failed (locked or not found?)\n"); return; }
        char *b64sig = b64_encode(sig, 64);
        snprintf(resp, sizeof(resp), "OK SIG:%s\n", b64sig ? b64sig : "");
        tx_send(resp);
        memset(sig, 0, sizeof(sig));
        if (b64sig) free(b64sig);
    } else if (strcasecmp(cmd, "WA_COUNT") == 0) {
        /* WA_COUNT —— 返回当前凭证数量（供网页快速统计） */
        int n = wa_list_count();
        snprintf(resp, sizeof(resp), "OK %d credentials\n", n < 0 ? 0 : n);
        tx_send(resp);
    } else if (strcasecmp(cmd, "WA_WIPE") == 0) {
        int n = wa_wipe();
        snprintf(resp, sizeof(resp), "OK wiped %d credentials\n", n < 0 ? 0 : n);
        tx_send(resp);
    } else {
        tx_send("ERR unknown command, send HELP\n");
    }
}

/* ---------- GATT 访问回调 ---------- */
static int gatt_access_cb(uint16_t ch, uint16_t attr, struct ble_gatt_access_ctxt *ctxt, void *arg) {
    if (ble_uuid_cmp(ctxt->chr->uuid, &nus_rx_uuid.u) == 0) {
        /* 收到手机写入 */
        uint16_t om_len = OS_MBUF_PKTLEN(ctxt->om);
        uint8_t tmp[512];
        if (om_len >= sizeof(tmp)) om_len = sizeof(tmp) - 1;
        uint16_t copied = 0;
        if (ble_hs_mbuf_to_flat(ctxt->om, tmp, om_len, &copied) != 0) {
            return BLE_ATT_ERR_UNLIKELY;
        }
        ESP_LOGI(TAG, "RX got %d bytes from attr=%d", copied, attr);
        /* 协议：每条命令以 4 位十六进制长度前缀开头（长度=命令体字节数），
         * 如 "0017ADD foo bar\n"。设备按长度收齐命令体再执行，彻底避免分片错乱。
         * 兼容：若开头不是 4 位 hex，则退回到“等换行”的旧模式。 */
        for (uint16_t i = 0; i < copied; i++) {
            char c = (char)tmp[i];
            rx_buf[rx_len++] = c;
            /* 收齐前缀后，计算期望长度 */
            if (rx_len == 4 && !rx_has_len) {
                if (is_hex4(rx_buf)) {
                    rx_has_len = true;
                    rx_expect = 4 + (size_t)strtoul_len4(rx_buf);
                } else {
                    rx_has_len = false; /* 无前缀，走旧模式 */
                    rx_expect = 0;
                }
            }
            /* 判断一条命令是否完整 */
            bool complete = false;
            if (rx_has_len) {
                complete = (rx_len >= rx_expect);
                if (complete) { rx_len = rx_expect; } /* 截掉多余 */
            } else {
                if (rx_len > 0 && (c == '\n' || c == '\r')) {
                    complete = true;
                    rx_len--; /* 去掉换行 */
                }
            }
            if (complete) {
                rx_buf[rx_len] = '\0';
                char *cmd_body = rx_has_len ? (rx_buf + 4) : rx_buf;
                ESP_LOGI(TAG, "exec cmd: '%s'", cmd_body);
                handle_command(cmd_body);
                rx_len = 0; rx_has_len = false; rx_expect = 0;
            }
            if (rx_len >= sizeof(rx_buf) - 1) { rx_len = 0; rx_has_len = false; rx_expect = 0; }
        }
        return 0;
    }
    if (ble_uuid_cmp(ctxt->chr->uuid, &nus_tx_uuid.u) == 0) {
        return 0; /* 通知特征，仅读描述符 */
    }
    return BLE_ATT_ERR_UNLIKELY;
}

/* ---------- GATT 服务定义 ---------- */
static const struct ble_gatt_chr_def nus_chrs[] = {
    {
        /* RX 特征：手机写入 → 设备接收 */
        .uuid = &nus_rx_uuid.u,
        .access_cb = gatt_access_cb,
        .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP,
    },
    {
        /* TX 特征：设备通知 → 手机接收 */
        .uuid = &nus_tx_uuid.u,
        .access_cb = gatt_access_cb,
        .flags = BLE_GATT_CHR_F_NOTIFY,
        .val_handle = &tx_val_handle,
    },
    {
        0, /* 结束标记 */
    },
};

static const struct ble_gatt_svc_def gatt_svcs[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &nus_svc_uuid.u,
        .characteristics = nus_chrs,
    },
    {
        0, /* 结束标记 */
    },
};

/* ---------- 连接事件 ---------- */
static int gap_event_cb(struct ble_gap_event *event, void *arg) {
    switch (event->type) {
        case BLE_GAP_EVENT_CONNECT:
            if (event->connect.status == 0) {
                conn_handle = event->connect.conn_handle;
                rx_len = 0;
                ESP_LOGI(TAG, "connected, handle=%d", conn_handle);
            } else {
                conn_handle = BLE_HS_CONN_HANDLE_NONE;
                ble_totp_start(); /* 重新广播 */
            }
            return 0;

        case BLE_GAP_EVENT_DISCONNECT:
            ESP_LOGI(TAG, "disconnected, reason=%d", event->disconnect.reason);
            conn_handle = BLE_HS_CONN_HANDLE_NONE;
            rx_len = 0;
            /* 断开即上锁：清掉内存中的主密钥，重新连接必须再 AUTHPASS */
            esp_crypto_lock();
            ble_totp_start();
            return 0;

        case BLE_GAP_EVENT_MTU:
            ESP_LOGI(TAG, "mtu update: %d", event->mtu.value);
            return 0;

        case BLE_GAP_EVENT_SUBSCRIBE:
            ESP_LOGI(TAG, "subscribe attr=%d notify=%d",
                     event->subscribe.attr_handle, event->subscribe.cur_notify);
            return 0;

        default:
            return 0;
    }
}

/* ---------- 广播 ---------- */
static void advertise(void) {
    /* 广播包里带 128-bit 服务 UUID 往往超出 31 字节广播包限制
     * （BLE_HS_EMSGSIZE），因此这里只用名字广播，服务用 GATT 发现。 */
    struct ble_hs_adv_fields fields = {0};
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.name = (uint8_t *)BLE_DEVICE_NAME;
    fields.name_len = strlen(BLE_DEVICE_NAME);
    fields.name_is_complete = 1;

    int rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "adv_set_fields rc=%d", rc);
        return;
    }

    struct ble_gap_adv_params adv_params = {0};
    adv_params.conn_mode = BLE_GAP_CONN_MODE_UND;
    adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;
    adv_params.itvl_min = BLE_GAP_ADV_ITVL_MS(100);
    adv_params.itvl_max = BLE_GAP_ADV_ITVL_MS(200);
    rc = ble_gap_adv_start(own_addr_type, NULL, BLE_HS_FOREVER,
                           &adv_params, gap_event_cb, NULL);
    if (rc != 0) ESP_LOGE(TAG, "adv_start rc=%d", rc);
}

static void on_sync(void) {
    int rc = ble_hs_util_ensure_addr(0);
    if (rc != 0) {
        ESP_LOGE(TAG, "ensure_addr rc=%d", rc);
        return;
    }
    rc = ble_hs_id_infer_auto(0, &own_addr_type);
    if (rc != 0) {
        ESP_LOGE(TAG, "infer_auto rc=%d", rc);
        return;
    }

    /* 服务已在 ble_totp_init_and_run() 中注册，这里只需广播 */
    ESP_LOGI(TAG, "stack synced, advertising");
    ble_gatts_show_local();

    advertise();
}

static void on_reset(int reason) {
    ESP_LOGW(TAG, "host reset, reason=%d", reason);
}

/* 重新开始广播（断开连接后调用） */
void ble_totp_handle_line(char *line) {
    handle_command(line);
}

/* ---------- 串口命令通道 ----------
 * 读 USB-Serial/JTAG 控制台输入，按行喂给 handle_command。
 * 与 BLE 共用同一套命令解析（handle_command 内部无持久状态，安全）。
 */
static void console_task(void *arg) {
    (void)arg;
    char line[2048];
    size_t len = 0;
    while (1) {
        int c = getchar();
        if (c == EOF) { vTaskDelay(pdMS_TO_TICKS(20)); continue; }
        if (c == '\r' || c == '\n') {
            if (len > 0) {
                line[len] = '\0';
                ESP_LOGI(TAG, "console cmd: '%s'", line);
                /* 命令回复走 BLE 通知；串口只负责收命令 */
                handle_command(line);
                len = 0;
            }
            continue;
        }
        if (len < sizeof(line) - 1) line[len++] = (char)c;
        else len = 0; /* 过长丢弃 */
    }
}

void ble_totp_start_console(void) {
    xTaskCreate(console_task, "wa_console", 4096, NULL, 5, NULL);
}

void ble_totp_start(void) {
    advertise();
}

static void host_task(void *param) {
    nimble_port_run();
    nimble_port_freertos_deinit();
}

void ble_totp_init_and_run(void) {
    /* 设备身份：加载或生成 ECDSA P-256 密钥对，串口打印公钥供 CA 签名 */
    espid_init();

    esp_err_t rc = nimble_port_init();
    if (rc != ESP_OK) {
        ESP_LOGE(TAG, "nimble init failed: %d", rc);
        return;
    }
    ble_hs_cfg.sync_cb = on_sync;
    ble_hs_cfg.reset_cb = on_reset;
    ble_svc_gap_init();
    ble_svc_gatt_init();
    ble_svc_gap_device_name_set(BLE_DEVICE_NAME);

    /* 关键！服务注册必须在 nimble_port_freertos_init() 之前完成。
     * 因为协议栈启动时会自动调用 ble_gatts_start()，它会把此时
     * 已经 add 进来的 svc_defs 注册进 GATT 数据库。若等到 sync 回调
     * 才 add，ble_gatts_start() 已经跑过了，服务就永远不会生效。
     */
    int rc2 = ble_gatts_count_cfg(gatt_svcs);
    ESP_LOGI(TAG, "count_cfg rc=%d", rc2);
    if (rc2 != 0) return;
    rc2 = ble_gatts_add_svcs(gatt_svcs);
    ESP_LOGI(TAG, "add_svcs rc=%d", rc2);
    if (rc2 != 0) return;
    ESP_LOGI(TAG, "GATT svc defs added (will be registered at stack start)");

    nimble_port_freertos_init(host_task);
}
