/*
 * crypto.c - 设备身份与加密通讯（CA 信任链模型 ESP 端）
 */
#include "crypto.h"

#include <string.h>
#include <stdio.h>

#include "esp_log.h"
#include "esp_random.h"
#include "nvs.h"
#include "nvs_flash.h"

#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

static const char *TAG = "espid";

#define NVS_NS        "espid"
#define KEY_PRIV      "priv"      /* 设备私钥（DER） */
#define KEY_CERT      "cert"      /* CA 签发的证书（DER） */
#define KEY_PASSHASH  "passhash"  /* 密码派生值（32B 盐 + 32B hash） */

static mbedtls_ecp_keypair s_key;      /* 设备密钥对（内存中） */
static bool s_key_loaded = false;

/* ---- RNG ---- */
static mbedtls_entropy_context  s_entropy;
static mbedtls_ctr_drbg_context s_drbg;
static bool s_rng_ready = false;

static int ensure_rng(void) {
    if (s_rng_ready) return 0;
    mbedtls_entropy_init(&s_entropy);
    mbedtls_ctr_drbg_init(&s_drbg);
    const char *pers = "atri-totp-espid";
    int rc = mbedtls_ctr_drbg_seed(&s_drbg, mbedtls_entropy_func, &s_entropy,
                                   (const unsigned char *)pers, strlen(pers));
    if (rc != 0) {
        ESP_LOGE(TAG, "ctr_drbg_seed failed -0x%04x", -rc);
        return rc;
    }
    s_rng_ready = true;
    return 0;
}

/* ---- NVS 辅助 ---- */
static esp_err_t nvs_get_blob_len(const char *key, size_t *out_len) {
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READONLY, &h);
    if (err != ESP_OK) return err;
    size_t len = 0;
    err = nvs_get_blob(h, key, NULL, &len);
    nvs_close(h);
    if (err == ESP_OK && out_len) *out_len = len;
    return err;
}

/* ---- 生成 / 加载密钥 ---- */
static esp_err_t gen_key(void) {
    if (ensure_rng() != 0) return ESP_FAIL;
    mbedtls_ecp_keypair_init(&s_key);
    int rc = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &s_key,
                                 mbedtls_ctr_drbg_random, &s_drbg);
    if (rc != 0) {
        ESP_LOGE(TAG, "gen_key failed -0x%04x", -rc);
        return ESP_FAIL;
    }
    /* 序列化私钥为 DER 存 NVS */
    uint8_t buf[256];
    size_t olen = 0;
    rc = mbedtls_ecp_write_key_ext(&s_key, &olen, buf, sizeof(buf));
    if (rc != 0) {
        ESP_LOGE(TAG, "write_key failed -0x%04x", -rc);
        return ESP_FAIL;
    }
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(h, KEY_PRIV, buf, olen);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "store priv failed %d", err);
        return err;
    }
    s_key_loaded = true;
    ESP_LOGI(TAG, "generated new ECDSA P-256 device key");
    return ESP_OK;
}

static esp_err_t load_key(void) {
    size_t len = 0;
    if (nvs_get_blob_len(KEY_PRIV, &len) != ESP_OK) return ESP_ERR_NOT_FOUND;
    uint8_t buf[256];
    if (len > sizeof(buf)) return ESP_ERR_INVALID_SIZE;
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READONLY, &h);
    if (err != ESP_OK) return err;
    size_t rlen = len;
    err = nvs_get_blob(h, KEY_PRIV, buf, &rlen);
    nvs_close(h);
    if (err != ESP_OK) return err;

    mbedtls_ecp_keypair_init(&s_key);
    int rc = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &s_key, buf, rlen);
    if (rc != 0) {
        ESP_LOGE(TAG, "read_key failed -0x%04x", -rc);
        return ESP_FAIL;
    }
    /* mbedTLS 3.x 的 read_key 只设置私钥 d，公钥点 Q 是空的，
     * 必须手动由 d 计算出 Q，否则导出的公钥是空点。 */
    if (ensure_rng() != 0) return ESP_FAIL;
    rc = mbedtls_ecp_keypair_calc_public(&s_key,
                                         mbedtls_ctr_drbg_random, &s_drbg);
    if (rc != 0) {
        ESP_LOGE(TAG, "calc_public failed -0x%04x", -rc);
        return ESP_FAIL;
    }
    s_key_loaded = true;
    return ESP_OK;
}

esp_err_t espid_init(void) {
    esp_err_t err = load_key();
    if (err == ESP_ERR_NOT_FOUND) {
        err = gen_key();
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "espid_init failed %d", err);
        return err;
    }

    /* 打印设备公钥（未压缩点，65 字节）与指纹，供电脑 CA 签名 */
    uint8_t pub[65];
    int plen = espid_get_pubkey(pub, sizeof(pub));
    ESP_LOGI(TAG, "pubkey dump: plen=%d, s_key_loaded=%d", plen, s_key_loaded);
    if (plen > 0) {
        char hex[65 * 2 + 1];
        for (int i = 0; i < plen; i++) sprintf(hex + i * 2, "%02x", pub[i]);
        hex[plen * 2] = 0;
        ESP_LOGI(TAG, "DEVICE PUBKEY: %s", hex);
        uint8_t fp[32];
        if (espid_get_pubkey_fingerprint(fp) == 32) {
            char fhex[65];
            for (int i = 0; i < 32; i++) sprintf(fhex + i * 2, "%02x", fp[i]);
            fhex[64] = 0;
            ESP_LOGI(TAG, "DEVICE FINGERPRINT: %s", fhex);
        }
    }
    ESP_LOGI(TAG, "cert installed: %s", espid_has_cert() ? "yes" : "no");
    return ESP_OK;
}

bool espid_has_key(void) { return s_key_loaded; }

bool espid_has_cert(void) {
    size_t len = 0;
    return nvs_get_blob_len(KEY_CERT, &len) == ESP_OK && len > 0;
}

int espid_get_pubkey(uint8_t *out, size_t cap) {
    if (!s_key_loaded || cap < 65) return -1;
    size_t olen = 0;
    int rc = mbedtls_ecp_write_public_key(&s_key, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                          &olen, out, cap);
    if (rc != 0) {
        ESP_LOGE(TAG, "write_public_key failed -0x%04x", -rc);
        return -1;
    }
    return (int)olen;
}

int espid_get_pubkey_fingerprint(uint8_t out[32]) {
    uint8_t pub[65];
    int plen = espid_get_pubkey(pub, sizeof(pub));
    if (plen <= 0) return -1;
    mbedtls_sha256(pub, plen, out, 0);
    return 32;
}

int espid_sign(const uint8_t *data, size_t len, uint8_t *sig_out, size_t cap) {
    if (!s_key_loaded) return -1;
    if (ensure_rng() != 0) return -1;
    uint8_t hash[32];
    mbedtls_sha256(data, len, hash, 0);

    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
    /* 必须先加载曲线，否则导出的 grp 无曲线参数，签名会失败/验不过 */
    int rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (rc != 0) { goto cleanup; }
    rc = mbedtls_ecp_export(&s_key, &grp, &d, &Q);
    if (rc != 0) { goto cleanup; }

    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    rc = mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, sizeof(hash),
                            mbedtls_ctr_drbg_random, &s_drbg);
    if (rc != 0) {
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        goto cleanup;
    }
    /* 将 r,s 序列化为原始 64 字节（大端 r||s），方便网页 WebCrypto 直接导入 */
    size_t rlen = mbedtls_mpi_size(&r);
    size_t slen = mbedtls_mpi_size(&s);
    if (rlen > 32 || slen > 32 || 64 > cap) {
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        rc = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }
    memset(sig_out, 0, 64);
    mbedtls_mpi_write_binary(&r, sig_out + (32 - rlen), rlen);
    mbedtls_mpi_write_binary(&s, sig_out + 32 + (32 - slen), slen);

    /* 自检：用同一公钥点验证签名，确认 grp/d/sig 都正确 */
    {
        mbedtls_mpi rr, ss;
        mbedtls_mpi_init(&rr);
        mbedtls_mpi_init(&ss);
        mbedtls_mpi_read_binary(&rr, sig_out, 32);
        mbedtls_mpi_read_binary(&ss, sig_out + 32, 32);
        int vrc = mbedtls_ecdsa_verify(&grp, hash, sizeof(hash), &Q, &rr, &ss);
        ESP_LOGI(TAG, "sign self-check: %s (rlen=%d slen=%d)",
                 vrc == 0 ? "OK" : "FAIL", (int)rlen, (int)slen);
        mbedtls_mpi_free(&rr);
        mbedtls_mpi_free(&ss);
    }

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    rc = 0;

cleanup:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
    return (rc == 0) ? 64 : -1;
}

esp_err_t espid_set_cert(const uint8_t *der, size_t len) {
    if (!der || len == 0 || len > 1024) return ESP_ERR_INVALID_ARG;
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(h, KEY_CERT, der, len);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

int espid_get_cert(uint8_t *out, size_t cap) {
    size_t len = 0;
    if (nvs_get_blob_len(KEY_CERT, &len) != ESP_OK) return -1;
    if (len > cap) return -1;
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return -1;
    size_t rlen = len;
    esp_err_t err = nvs_get_blob(h, KEY_CERT, out, &rlen);
    nvs_close(h);
    if (err != ESP_OK) return -1;
    return (int)rlen;
}

/* ---------- 密码（盐 + SHA-256 多轮） ---------- */
static void derive_pass(const char *password, const uint8_t salt[16], uint8_t out[32]) {
    /* 简易 PBKDF2-like：盐 + 密码，迭代 10000 次 SHA256 */
    uint8_t buf[16 + 128];
    size_t plen = strlen(password);
    if (plen > 128) plen = 128;
    memcpy(buf, salt, 16);
    memcpy(buf + 16, password, plen);
    size_t blen = 16 + plen;
    mbedtls_sha256(buf, blen, out, 0);
    for (int i = 0; i < 10000; i++) {
        uint8_t tmp[32];
        memcpy(tmp, out, 32);
        mbedtls_sha256(tmp, 32, out, 0);
    }
}

bool esp_pass_is_set(void) {
    size_t len = 0;
    return nvs_get_blob_len(KEY_PASSHASH, &len) == ESP_OK && len == 48;
}

esp_err_t esp_pass_set(const char *password) {
    if (!password || strlen(password) < 4) return ESP_ERR_INVALID_ARG;
    uint8_t salt[16];
    esp_fill_random(salt, sizeof(salt));
    uint8_t hash[32];
    derive_pass(password, salt, hash);
    uint8_t blob[48];
    memcpy(blob, salt, 16);
    memcpy(blob + 16, hash, 32);

    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(h, KEY_PASSHASH, blob, sizeof(blob));
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

bool esp_pass_verify(const char *password) {
    if (!password) return false;
    size_t len = 0;
    if (nvs_get_blob_len(KEY_PASSHASH, &len) != ESP_OK || len != 48) return false;
    uint8_t blob[48];
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return false;
    size_t rlen = sizeof(blob);
    esp_err_t err = nvs_get_blob(h, KEY_PASSHASH, blob, &rlen);
    nvs_close(h);
    if (err != ESP_OK) return false;

    uint8_t hash[32];
    derive_pass(password, blob, hash);
    /* 恒定时间比较 */
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++) diff |= hash[i] ^ blob[16 + i];
    return diff == 0;
}

esp_err_t esp_pass_reset(const char *new_password) {
    return esp_pass_set(new_password);
}

/* ---------- 数据加密（AES-256-GCM，密钥由密码派生） ---------- */
#include "mbedtls/gcm.h"

static uint8_t s_master_key[32];   /* 密码派生的主密钥（内存中） */
static bool s_unlocked = false;

bool esp_crypto_unlocked(void) { return s_unlocked; }

void esp_crypto_lock(void) {
    memset(s_master_key, 0, sizeof(s_master_key));
    s_unlocked = false;
}

/* 从密码派生主密钥（与密码哈希不同的区分串，避免同值复用） */
static void derive_master_key(const char *password, const uint8_t salt[16], uint8_t out[32]) {
    uint8_t buf[16 + 128 + 16];
    size_t plen = strlen(password);
    if (plen > 128) plen = 128;
    memcpy(buf, salt, 16);
    /* 加区分串 "ATRI-MK-ENC"，与登录哈希分开 */
    memcpy(buf + 16, "ATRI-MK-ENC", 11);
    memcpy(buf + 27, password, plen);
    size_t blen = 27 + plen;
    mbedtls_sha256(buf, blen, out, 0);
    for (int i = 0; i < 10000; i++) {
        uint8_t tmp[32];
        memcpy(tmp, out, 32);
        mbedtls_sha256(tmp, 32, out, 0);
    }
}

int esp_crypto_unlock(const char *password) {
    if (!password) return -1;
    size_t len = 0;
    if (nvs_get_blob_len(KEY_PASSHASH, &len) != ESP_OK || len != 48) return -1;
    uint8_t blob[48];
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return -1;
    size_t rlen = sizeof(blob);
    esp_err_t err = nvs_get_blob(h, KEY_PASSHASH, blob, &rlen);
    nvs_close(h);
    if (err != ESP_OK) return -1;

    /* 先校验密码正确 */
    uint8_t hash[32];
    derive_pass(password, blob, hash);
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++) diff |= hash[i] ^ blob[16 + i];
    if (diff != 0) return -1;

    /* 派生主密钥并缓存 */
    derive_master_key(password, blob, s_master_key);
    s_unlocked = true;
    return 0;
}

int esp_crypto_encrypt(const uint8_t *in, size_t len, uint8_t *out, size_t cap) {
    if (!s_unlocked) return -1;
    if (cap < len + 28) return -1;
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, s_master_key, 256);
    if (rc != 0) { mbedtls_gcm_free(&ctx); return -1; }

    uint8_t *nonce = out;
    esp_fill_random(nonce, 12);
    uint8_t *ct = out + 12;
    uint8_t *tag = out + 12 + len;
    rc = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, len, nonce, 12,
                                   NULL, 0, in, ct, 16, tag);
    mbedtls_gcm_free(&ctx);
    if (rc != 0) return -1;
    return (int)(len + 28);
}

int esp_crypto_decrypt(const uint8_t *in, size_t len, uint8_t *out, size_t cap) {
    if (!s_unlocked) return -1;
    if (len < 28) return -1;
    size_t ctlen = len - 28;
    if (cap < ctlen) return -1;
    const uint8_t *nonce = in;
    const uint8_t *ct = in + 12;
    const uint8_t *tag = in + 12 + ctlen;
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, s_master_key, 256);
    if (rc != 0) { mbedtls_gcm_free(&ctx); return -1; }
    rc = mbedtls_gcm_auth_decrypt(&ctx, ctlen, nonce, 12, NULL, 0,
                                  tag, 16, ct, out);
    mbedtls_gcm_free(&ctx);
    if (rc != 0) return -1;
    return (int)ctlen;
}

/* ---------- 钱包私钥（secp256k1，只进不出） ---------- */
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"

#define W_NS "wallet"

/* 钱包槽位 key: w00..w07，value = 加密的 label(32) + 
 * priv(32)，共 64 字节明文 */
static void w_slot_key(int i, char *out, size_t cap) { snprintf(out, cap, "w%02d", i); }

static int w_find(nvs_handle_t h, const char *label, uint8_t *blob_out, size_t *blob_len) {
    for (int i = 0; i < WALLET_MAX_KEYS; i++) {
        char k[8]; w_slot_key(i, k, sizeof(k));
        uint8_t buf[160];
        size_t len = sizeof(buf);
        if (nvs_get_blob(h, k, buf, &len) != ESP_OK) continue;
        uint8_t plain[128];
        int pl = esp_crypto_decrypt(buf, len, plain, sizeof(plain));
        if (pl < 64) continue;
        /* plain[0..31] = label */
        char lbl[WALLET_MAX_NAME];
        memcpy(lbl, plain, WALLET_MAX_NAME); lbl[WALLET_MAX_NAME-1]=0;
        if (strncmp(lbl, label, WALLET_MAX_NAME) == 0) {
            if (blob_out && blob_len) { memcpy(blob_out, buf, len); *blob_len = len; }
            return i;
        }
    }
    return -1;
}

static int w_free_slot(nvs_handle_t h) {
    for (int i = 0; i < WALLET_MAX_KEYS; i++) {
        char k[8]; w_slot_key(i, k, sizeof(k));
        size_t len = 0;
        if (nvs_get_blob(h, k, NULL, &len) != ESP_OK) return i;
    }
    return -1;
}

esp_err_t wallet_import(const char *label, const uint8_t priv[32]) {
    if (!label || !priv) return ESP_ERR_INVALID_ARG;
    if (!esp_crypto_unlocked()) return ESP_ERR_INVALID_STATE;
    size_t ll = strlen(label);
    if (ll == 0 || ll >= WALLET_MAX_NAME) return ESP_ERR_INVALID_ARG;

    /* 明文 = label(32) || priv(32) */
    uint8_t plain[64];
    memset(plain, 0, sizeof(plain));
    memcpy(plain, label, ll);
    memcpy(plain + WALLET_MAX_NAME, priv, 32);

    uint8_t enc[64 + 32];
    int el = esp_crypto_encrypt(plain, sizeof(plain), enc, sizeof(enc));
    if (el <= 0) return ESP_FAIL;

    nvs_handle_t h;
    esp_err_t err = nvs_open(W_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    int slot = w_find(h, label, NULL, NULL);
    if (slot < 0) slot = w_free_slot(h);
    if (slot < 0) { nvs_close(h); return ESP_ERR_NO_MEM; }
    char k[8]; w_slot_key(slot, k, sizeof(k));
    err = nvs_set_blob(h, k, enc, el);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

int wallet_list(char *buf, size_t cap) {
    if (!buf || cap == 0) return -1;
    buf[0] = 0;
    if (!esp_crypto_unlocked()) return -1;
    nvs_handle_t h;
    if (nvs_open(W_NS, NVS_READONLY, &h) != ESP_OK) return 0;
    int n = 0; size_t used = 0;
    for (int i = 0; i < WALLET_MAX_KEYS; i++) {
        char k[8]; w_slot_key(i, k, sizeof(k));
        uint8_t b[160]; size_t len = sizeof(b);
        if (nvs_get_blob(h, k, b, &len) != ESP_OK) continue;
        uint8_t plain[128];
        int pl = esp_crypto_decrypt(b, len, plain, sizeof(plain));
        if (pl < 64) continue;
        char lbl[WALLET_MAX_NAME];
        memcpy(lbl, plain, WALLET_MAX_NAME); lbl[WALLET_MAX_NAME-1]=0;
        int w = snprintf(buf + used, cap - used, "%s;", lbl);
        if (w > 0 && (size_t)w < cap - used) used += w;
        n++;
    }
    nvs_close(h);
    return n;
}

int wallet_del(const char *label) {
    if (!label || !esp_crypto_unlocked()) return -1;
    nvs_handle_t h;
    if (nvs_open(W_NS, NVS_READWRITE, &h) != ESP_OK) return -1;
    int slot = w_find(h, label, NULL, NULL);
    if (slot < 0) { nvs_close(h); return -1; }
    char k[8]; w_slot_key(slot, k, sizeof(k));
    esp_err_t err = nvs_erase_key(h, k);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return (err == ESP_OK) ? 0 : -1;
}

int wallet_wipe(void) {
    nvs_handle_t h;
    if (nvs_open(W_NS, NVS_READWRITE, &h) != ESP_OK) return -1;
    int cnt = 0;
    for (int i = 0; i < WALLET_MAX_KEYS; i++) {
        char k[8]; w_slot_key(i, k, sizeof(k));
        size_t len = 0;
        if (nvs_get_blob(h, k, NULL, &len) == ESP_OK) {
            if (nvs_erase_key(h, k) == ESP_OK) cnt++;
        }
    }
    nvs_commit(h);
    nvs_close(h);
    return cnt;
}

/* 从加密存储中取出私钥到内存（仅内部用，不外泄） */
static int w_get_priv(const char *label, uint8_t priv_out[32]) {
    if (!esp_crypto_unlocked()) return -1;
    nvs_handle_t h;
    if (nvs_open(W_NS, NVS_READONLY, &h) != ESP_OK) return -1;
    int slot = w_find(h, label, NULL, NULL);
    if (slot < 0) { nvs_close(h); return -1; }
    char k[8]; w_slot_key(slot, k, sizeof(k));
    uint8_t b[160]; size_t len = sizeof(b);
    if (nvs_get_blob(h, k, b, &len) != ESP_OK) { nvs_close(h); return -1; }
    nvs_close(h);
    uint8_t plain[128];
    int pl = esp_crypto_decrypt(b, len, plain, sizeof(plain));
    if (pl < 64) return -1;
    memcpy(priv_out, plain + WALLET_MAX_NAME, 32);
    /* 清除栈上的明文副本 */
    memset(plain, 0, sizeof(plain));
    return 0;
}

int wallet_get_pubkey(const char *label, uint8_t *out, size_t cap) {
    if (!out || cap < 33) return -1;
    uint8_t priv[32];
    if (w_get_priv(label, priv) != 0) return -1;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d);
    int rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1);
    if (rc == 0) rc = mbedtls_mpi_read_binary(&d, priv, 32);
    if (rc == 0) rc = mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, NULL, NULL);
    size_t olen = 0;
    if (rc == 0) rc = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_COMPRESSED, &olen, out, cap);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    memset(priv, 0, sizeof(priv));
    if (rc != 0) return -1;
    return (int)olen;
}

int wallet_sign_hash(const char *label, const uint8_t hash32[32], uint8_t *out, size_t cap) {
    if (!out || cap < 64) return -1;
    uint8_t priv[32];
    if (w_get_priv(label, priv) != 0) return -1;
    if (ensure_rng() != 0) { memset(priv, 0, 32); return -1; }

    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d); mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
    int rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1);
    if (rc == 0) rc = mbedtls_mpi_read_binary(&d, priv, 32);
    if (rc == 0) rc = mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash32, 32,
                                         mbedtls_ctr_drbg_random, &s_drbg);
    if (rc == 0) {
        size_t rl = mbedtls_mpi_size(&r), sl = mbedtls_mpi_size(&s);
        if (rl <= 32 && sl <= 32) {
            memset(out, 0, 64);
            mbedtls_mpi_write_binary(&r, out + (32 - rl), rl);
            mbedtls_mpi_write_binary(&s, out + 32 + (32 - sl), sl);
        } else rc = -1;
    }
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d); mbedtls_mpi_free(&r); mbedtls_mpi_free(&s);
    memset(priv, 0, sizeof(priv));
    return (rc == 0) ? 64 : -1;
}
