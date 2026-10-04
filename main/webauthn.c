/*
 * webauthn.c - 网络凭证（WebAuthn / FIDO2 风格的硬件认证器）实现
 *
 * 存储布局（NVS 命名空间 "wan"）：
 *   slot_i : 某把凭证的密文 blob = AES-256-GCM(
 *              "id(16)||rp(64)||user(64)||priv(32)||meta(WA_META_LEN)" )
 *            —— 用密码派生的主密钥加密，须先 AUTHPASS 解锁才能读写
 *   meta 包含 created/sign_count/alg/cred_protect/discoverable/backup_state/
 *   user_id/user_display 等完整 WebAuthn 元数据。
 * 私钥只进不出：外部只能拿到公钥 / 凭证 ID / 元信息，唯一用到私钥的操作是签名。
 */
#include "webauthn.h"
#include "crypto.h"

#include <string.h>
#include <stdio.h>

#include "esp_log.h"
#include "esp_random.h"
#include "nvs.h"

#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ctr_drbg.h"

static const char *TAG = "webauthn";

#define WA_NS         "wan"
/* 元数据在密文 blob 中的序列化长度（定长、紧凑）*/
#define WA_META_LEN   (8 + 4 + 4 + 1 + 1 + 1 + 1 + WA_MAX_UID + 1 + WA_MAX_DISPLAY + 1 + WA_MAX_WEBID)
#define WA_PLAIN_LEN  (WA_ID_LEN + WA_MAX_RP + WA_MAX_USER + 32 + WA_META_LEN)
#define WA_META_OFF   (WA_ID_LEN + WA_MAX_RP + WA_MAX_USER + 32)

/* 把 wa_meta_t 序列化到定长缓冲区（大端）*/
static void meta_serialize(const wa_meta_t *m, uint8_t *out) {
    memset(out, 0, WA_META_LEN);
    size_t o = 0;
    for (int i = 7; i >= 0; i--) out[o++] = (uint8_t)(m->created >> (8 * i));
    for (int i = 3; i >= 0; i--) out[o++] = (uint8_t)(m->sign_count >> (8 * i));
    for (int i = 3; i >= 0; i--) out[o++] = (uint8_t)((uint32_t)m->alg >> (8 * i));
    out[o++] = m->cred_protect;
    out[o++] = m->discoverable;
    out[o++] = m->backup_state;
    uint8_t uid_len = m->user_id_len > WA_MAX_UID ? WA_MAX_UID : m->user_id_len;
    out[o++] = uid_len;
    memcpy(out + o, m->user_id, WA_MAX_UID); o += WA_MAX_UID;
    uint8_t dis_len = m->user_display_len > WA_MAX_DISPLAY ? WA_MAX_DISPLAY : m->user_display_len;
    out[o++] = dis_len;
    memcpy(out + o, m->user_display, WA_MAX_DISPLAY); o += WA_MAX_DISPLAY;
    uint8_t wid_len = m->web_id_len > WA_MAX_WEBID ? WA_MAX_WEBID : m->web_id_len;
    out[o++] = wid_len;
    memcpy(out + o, m->web_id, WA_MAX_WEBID);
}

/* 从定长缓冲区反序列化到 wa_meta_t */
static void meta_deserialize(const uint8_t *in, wa_meta_t *m) {
    memset(m, 0, sizeof(*m));
    size_t o = 0;
    for (int i = 0; i < 8; i++) m->created = (m->created << 8) | in[o++];
    for (int i = 0; i < 4; i++) m->sign_count = (m->sign_count << 8) | in[o++];
    uint32_t alg = 0;
    for (int i = 0; i < 4; i++) alg = (alg << 8) | in[o++];
    m->alg = (int32_t)alg;
    m->cred_protect = in[o++];
    m->discoverable = in[o++];
    m->backup_state = in[o++];
    m->user_id_len = in[o++];
    if (m->user_id_len > WA_MAX_UID) m->user_id_len = WA_MAX_UID;
    memcpy(m->user_id, in + o, WA_MAX_UID); o += WA_MAX_UID;
    m->user_display_len = in[o++];
    if (m->user_display_len > WA_MAX_DISPLAY) m->user_display_len = WA_MAX_DISPLAY;
    memcpy(m->user_display, in + o, WA_MAX_DISPLAY); o += WA_MAX_DISPLAY;
    m->web_id_len = in[o++];
    if (m->web_id_len > WA_MAX_WEBID) m->web_id_len = WA_MAX_WEBID;
    memcpy(m->web_id, in + o, WA_MAX_WEBID);
}

/* ---- 复用 crypto.c 里的 RNG（通过一个薄封装：这里自建独立 DRBG） ---- */
/*
 * 为避免与 crypto.c 的静态 RNG 互相耦合，这里单独维护一份 CTR_DRBG，
 * 仅用于密钥生成。mbedTLS 的 entropy/ctr_drbg 都是可重入的独立上下文。
 */
#include "mbedtls/entropy.h"
static mbedtls_entropy_context  s_entropy;
static mbedtls_ctr_drbg_context s_drbg;
static bool s_rng_ready = false;

static int ensure_rng(void) {
    if (s_rng_ready) return 0;
    mbedtls_entropy_init(&s_entropy);
    mbedtls_ctr_drbg_init(&s_drbg);
    const char *pers = "atri-webauthn";
    int rc = mbedtls_ctr_drbg_seed(&s_drbg, mbedtls_entropy_func, &s_entropy,
                                   (const unsigned char *)pers, strlen(pers));
    if (rc != 0) {
        ESP_LOGE(TAG, "ctr_drbg_seed failed -0x%04x", -rc);
        return rc;
    }
    s_rng_ready = true;
    return 0;
}

/* ---- NVS 槽位键名 ---- */
static void slot_key(int i, char *out, size_t cap) {
    snprintf(out, cap, "wa%02d", i); /* wa00 ... wa07 */
}

/* 在 NVS 中按 id 查找槽位；返回槽号或 -1。解锁状态下的映射在 decrypt 时校验。 */
static int wa_find_slot_by_id(const uint8_t id[WA_ID_LEN]) {
    if (!esp_crypto_unlocked()) return -1;
    nvs_handle_t h;
    if (nvs_open(WA_NS, NVS_READONLY, &h) != ESP_OK) return -1;
    int found = -1;
    for (int i = 0; i < WA_MAX_CREDS; i++) {
        char k[8]; slot_key(i, k, sizeof(k));
        uint8_t b[WA_PLAIN_LEN + 32]; size_t len = sizeof(b);
        if (nvs_get_blob(h, k, b, &len) != ESP_OK) continue;
        uint8_t plain[WA_PLAIN_LEN + 32];
        int pl = esp_crypto_decrypt(b, len, plain, sizeof(plain));
        if (pl >= WA_ID_LEN && memcmp(plain, id, WA_ID_LEN) == 0) {
            found = i;
            memset(plain, 0, sizeof(plain));
            break;
        }
        memset(plain, 0, sizeof(plain));
    }
    nvs_close(h);
    return found;
}

static int wa_free_slot(void) {
    nvs_handle_t h;
    if (nvs_open(WA_NS, NVS_READONLY, &h) != ESP_OK) return 0;
    int slot = -1;
    for (int i = 0; i < WA_MAX_CREDS; i++) {
        char k[8]; slot_key(i, k, sizeof(k));
        size_t len = 0;
        if (nvs_get_blob(h, k, NULL, &len) != ESP_OK) { slot = i; break; }
    }
    nvs_close(h);
    return slot;
}

/* 按【对外 web credential id】查找槽位（用于 passless 的 read/delete 路径）。
 * 遍历所有槽位，解密后比对 meta.web_id。返回槽号或 -1。*/
static int wa_load_meta(int slot, wa_meta_t *out);
static int wa_find_slot_by_webid(const uint8_t *webid, size_t webid_len) {
    if (!webid || webid_len == 0 || webid_len > WA_MAX_WEBID) return -1;
    if (!esp_crypto_unlocked()) return -1;
    for (int i = 0; i < WA_MAX_CREDS; i++) {
        wa_meta_t m;
        if (wa_load_meta(i, &m) != 0) continue;
        if (m.web_id_len == webid_len && memcmp(m.web_id, webid, webid_len) == 0) {
            return i;
        }
    }
    return -1;
}

/* 把 id/rp/user/priv 打包加密后写入指定槽位 */
static int wa_store(int slot, const uint8_t id[WA_ID_LEN],
                    const char *rp, const char *user,
                    const uint8_t priv[32]) {
    uint8_t plain[WA_PLAIN_LEN];
    memset(plain, 0, sizeof(plain));
    memcpy(plain, id, WA_ID_LEN);
    memcpy(plain + WA_ID_LEN, rp, strnlen(rp, WA_MAX_RP - 1));
    memcpy(plain + WA_ID_LEN + WA_MAX_RP, user, strnlen(user, WA_MAX_USER - 1));
    memcpy(plain + WA_ID_LEN + WA_MAX_RP + WA_MAX_USER, priv, 32);

    uint8_t enc[WA_PLAIN_LEN + 32];
    int el = esp_crypto_encrypt(plain, sizeof(plain), enc, sizeof(enc));
    memset(plain, 0, sizeof(plain));
    if (el <= 0) return -1;

    nvs_handle_t h;
    if (nvs_open(WA_NS, NVS_READWRITE, &h) != ESP_OK) return -1;
    char k[8]; slot_key(slot, k, sizeof(k));
    esp_err_t err = nvs_set_blob(h, k, enc, el);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return (err == ESP_OK) ? 0 : -1;
}

/* 读取某槽位，解密出 id/rp/user/priv（任一可为 NULL）。返回 0 成功。 */
static int wa_load(int slot, uint8_t id[WA_ID_LEN],
                   char *rp_out, size_t rp_cap,
                   char *user_out, size_t user_cap,
                   uint8_t priv_out[32]) {
    if (!esp_crypto_unlocked()) return -1;
    nvs_handle_t h;
    if (nvs_open(WA_NS, NVS_READONLY, &h) != ESP_OK) return -1;
    char k[8]; slot_key(slot, k, sizeof(k));
    uint8_t b[WA_PLAIN_LEN + 32]; size_t len = sizeof(b);
    esp_err_t err = nvs_get_blob(h, k, b, &len);
    nvs_close(h);
    if (err != ESP_OK) return -1;

    uint8_t plain[WA_PLAIN_LEN + 32];
    int pl = esp_crypto_decrypt(b, len, plain, sizeof(plain));
    if (pl < WA_PLAIN_LEN) { memset(plain, 0, sizeof(plain)); return -1; }

    if (id) memcpy(id, plain, WA_ID_LEN);
    if (rp_out) {
        strncpy(rp_out, (char *)(plain + WA_ID_LEN), rp_cap - 1);
        rp_out[rp_cap - 1] = 0;
    }
    if (user_out) {
        strncpy(user_out, (char *)(plain + WA_ID_LEN + WA_MAX_RP), user_cap - 1);
        user_out[user_cap - 1] = 0;
    }
    if (priv_out) memcpy(priv_out, plain + WA_ID_LEN + WA_MAX_RP + WA_MAX_USER, 32);
    memset(plain, 0, sizeof(plain));
    return 0;
}

/* 读取某槽位的完整元数据（需要解锁）。返回 0 成功。*/
static int wa_load_meta(int slot, wa_meta_t *out) {
    if (!out) return -1;
    uint8_t id[WA_ID_LEN];
    if (wa_load(slot, id, NULL, 0, NULL, 0, NULL) != 0) return -1;
    /* 重新读一次明文以取 meta（简单起见，复用 wa_load 的解密）*/
    if (!esp_crypto_unlocked()) return -1;
    nvs_handle_t h;
    if (nvs_open(WA_NS, NVS_READONLY, &h) != ESP_OK) return -1;
    char k[8]; slot_key(slot, k, sizeof(k));
    uint8_t b[512]; size_t len = sizeof(b);
    esp_err_t err = nvs_get_blob(h, k, b, &len);
    nvs_close(h);
    if (err != ESP_OK) return -1;
    uint8_t plain[512];
    int pl = esp_crypto_decrypt(b, len, plain, sizeof(plain));
    if (pl < WA_PLAIN_LEN) { memset(plain, 0, sizeof(plain)); return -1; }
    meta_deserialize(plain + WA_META_OFF, out);
    memset(plain, 0, sizeof(plain));
    return 0;
}

/* 由 32 字节私钥算出公钥（未压缩点 65 字节）。返回 65 或 -1。 */
static int pubkey_from_priv(const uint8_t priv[32], uint8_t *out, size_t cap) {
    if (cap < 65) return -1;
    /* mbedTLS 3.x：grp.G 等成员已私有化，直接访问会导致 ecp_mul 报
     * BAD_INPUT_DATA(-0x4F80)。全程改用公开 keypair API：
     *   read_key -> keypair_calc_public -> write_public_key */
    mbedtls_ecp_keypair kp;
    mbedtls_ecp_keypair_init(&kp);
    int rc = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &kp, priv, 32);
    if (rc) ESP_LOGW(TAG, "pk: read_key rc=-0x%04x", -rc);
    if (rc == 0) { rc = mbedtls_ecp_keypair_calc_public(&kp, mbedtls_ctr_drbg_random, &s_drbg);
                   if (rc) ESP_LOGW(TAG, "pk: calc_public rc=-0x%04x", -rc); }
    size_t olen = 0;
    if (rc == 0) { rc = mbedtls_ecp_write_public_key(&kp, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                     &olen, out, cap);
                   if (rc) ESP_LOGW(TAG, "pk: write_pub rc=-0x%04x olen=%u cap=%u", -rc, (unsigned)olen, (unsigned)cap); }
    mbedtls_ecp_keypair_free(&kp);
    if (rc != 0 || olen != 65) return -1;
    return 65;
}

int wa_register(const char *rp, const char *user, uint8_t id_out[WA_ID_LEN]) {
    if (!rp || rp[0] == 0 || !id_out) return -1;
    if (!esp_crypto_unlocked()) return -1;
    if (ensure_rng() != 0) return -1;
    /* 注：默认元数据（created=0、alg=-7、discoverable=1、cred_protect=0、
     * backup_state=0）在 wa_store 里以零初始化写入，上层随后用
     * wa_set_meta() 补齐浏览器要求的完整元数据。*/

    /* 1. 生成 P-256 密钥对 -> 取 32 字节私钥 */
    mbedtls_ecp_keypair kp;
    mbedtls_ecp_keypair_init(&kp);
    int rc = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &kp,
                                 mbedtls_ctr_drbg_random, &s_drbg);
    uint8_t priv[32];
    size_t olen = 0;
    if (rc == 0) rc = mbedtls_ecp_write_key_ext(&kp, &olen, priv, sizeof(priv));
    mbedtls_ecp_keypair_free(&kp);
    if (rc != 0 || olen != 32) {
        memset(priv, 0, sizeof(priv));
        ESP_LOGE(TAG, "gen_key failed -0x%04x", -rc);
        return -1;
    }
    /* mbedtls_ecp_write_key_ext 输出大端定长私钥（32B） */

    /* 2. 随机凭证 ID */
    uint8_t id[WA_ID_LEN];
    esp_fill_random(id, sizeof(id));

    /* 3. 找一个空槽位（或覆盖同 rp+user 的旧凭证） */
    int slot = wa_free_slot();
    if (slot < 0) {
        /* 空间满：尝试覆盖同 rp+user 的旧凭证 */
        for (int i = 0; i < WA_MAX_CREDS && slot < 0; i++) {
            char r[WA_MAX_RP], u[WA_MAX_USER];
            if (wa_load(i, NULL, r, sizeof(r), u, sizeof(u), NULL) == 0) {
                if (strcmp(r, rp) == 0 && strcmp(u, user ? user : "") == 0) slot = i;
            }
        }
    }
    if (slot < 0) {
        memset(priv, 0, sizeof(priv));
        ESP_LOGW(TAG, "no free slot");
        return -1;
    }

    int st = wa_store(slot, id, rp, user ? user : "", priv);
    memset(priv, 0, sizeof(priv));
    if (st != 0) return -1;
    memcpy(id_out, id, WA_ID_LEN);
    ESP_LOGI(TAG, "registered credential for rp='%s' user='%s' (slot %d)",
             rp, user ? user : "", slot);
    return 0;
}

int wa_find_credential(const char *rp, const char *user, uint8_t id_out[WA_ID_LEN]) {
    if (!rp || !id_out || !esp_crypto_unlocked()) return -1;
    for (int i = 0; i < WA_MAX_CREDS; i++) {
        uint8_t id[WA_ID_LEN];
        char r[WA_MAX_RP], u[WA_MAX_USER];
        if (wa_load(i, id, r, sizeof(r), u, sizeof(u), NULL) != 0) continue;
        if (strcmp(r, rp) != 0) continue;
        if (user && user[0] && strcmp(u, user) != 0) continue;
        memcpy(id_out, id, WA_ID_LEN);
        return 0;
    }
    return -1;
}

/* 更新某槽位的 rp / user 字段（覆写 WA_REG 时的占位值）。
 * rp/user 为 NULL 时保持该字段不变。返回 0 成功。*/
int wa_update_rp_user(const uint8_t id[WA_ID_LEN], const char *rp, const char *user) {
    if (!id) return -1;
    if (!esp_crypto_unlocked()) return -1;
    int slot = wa_find_slot_by_id(id);
    if (slot < 0) return -1;

    nvs_handle_t h;
    if (nvs_open(WA_NS, NVS_READONLY, &h) != ESP_OK) return -1;
    char k[8]; slot_key(slot, k, sizeof(k));
    uint8_t b[WA_PLAIN_LEN + 32]; size_t len = sizeof(b);
    esp_err_t err = nvs_get_blob(h, k, b, &len);
    nvs_close(h);
    if (err != ESP_OK) return -1;

    uint8_t plain[WA_PLAIN_LEN + 32];
    int pl = esp_crypto_decrypt(b, len, plain, sizeof(plain));
    if (pl < WA_PLAIN_LEN) { memset(plain, 0, sizeof(plain)); return -1; }

    if (rp) {
        memset(plain + WA_ID_LEN, 0, WA_MAX_RP);
        memcpy(plain + WA_ID_LEN, rp, strnlen(rp, WA_MAX_RP - 1));
    }
    if (user) {
        memset(plain + WA_ID_LEN + WA_MAX_RP, 0, WA_MAX_USER);
        memcpy(plain + WA_ID_LEN + WA_MAX_RP, user, strnlen(user, WA_MAX_USER - 1));
    }

    uint8_t enc[WA_PLAIN_LEN + 32];
    int el = esp_crypto_encrypt(plain, WA_PLAIN_LEN, enc, sizeof(enc));
    memset(plain, 0, sizeof(plain));
    if (el <= 0) return -1;

    if (nvs_open(WA_NS, NVS_READWRITE, &h) != ESP_OK) return -1;
    err = nvs_set_blob(h, k, enc, el);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return (err == ESP_OK) ? 0 : -1;
}

int wa_get_pubkey(const uint8_t id[WA_ID_LEN], uint8_t *out, size_t cap) {
    if (!id || !out) return -1;
    int slot = wa_find_slot_by_id(id);
    if (slot < 0) return -1;
    uint8_t priv[32];
    if (wa_load(slot, NULL, NULL, 0, NULL, 0, priv) != 0) return -1;
    int r = pubkey_from_priv(priv, out, cap);
    memset(priv, 0, sizeof(priv));
    return r;
}

int wa_get_meta(const uint8_t id[WA_ID_LEN],
                char *rp_out, size_t rp_cap,
                char *user_out, size_t user_cap) {
    if (!id) return -1;
    int slot = wa_find_slot_by_id(id);
    if (slot < 0) return -1;
    return wa_load(slot, NULL, rp_out, rp_cap, user_out, user_cap, NULL);
}

int wa_get_meta_full(const uint8_t id[WA_ID_LEN], wa_meta_t *out) {
    if (!id || !out) return -1;
    int slot = wa_find_slot_by_id(id);
    if (slot < 0) return -1;
    return wa_load_meta(slot, out);
}

/* ---- 按对外 web credential id 操作的包装（供 passless 使用）---- */

int wa_get_id_meta_by_webid(const uint8_t *webid, size_t webid_len,
                            uint8_t id_out[WA_ID_LEN], wa_meta_t *meta_out) {
    int slot = wa_find_slot_by_webid(webid, webid_len);
    if (slot < 0) return -1;
    if (wa_load(slot, id_out, NULL, 0, NULL, 0, NULL) != 0) return -1;
    if (meta_out) return wa_load_meta(slot, meta_out);
    return 0;
}

int wa_get_meta_by_webid(const uint8_t *webid, size_t webid_len,
                         char *rp_out, size_t rp_cap,
                         char *user_out, size_t user_cap,
                         wa_meta_t *meta_out) {
    int slot = wa_find_slot_by_webid(webid, webid_len);
    if (slot < 0) return -1;
    if (rp_out || user_out) {
        if (wa_load(slot, NULL, rp_out, rp_cap, user_out, user_cap, NULL) != 0) return -1;
    }
    if (meta_out) return wa_load_meta(slot, meta_out);
    return 0;
}

int wa_delete_by_webid(const uint8_t *webid, size_t webid_len) {
    int slot = wa_find_slot_by_webid(webid, webid_len);
    if (slot < 0) return -1;
    if (!esp_crypto_unlocked()) return -1;
    nvs_handle_t h;
    if (nvs_open(WA_NS, NVS_READWRITE, &h) != ESP_OK) return -1;
    char k[8]; slot_key(slot, k, sizeof(k));
    esp_err_t err = nvs_erase_key(h, k);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return (err == ESP_OK) ? 0 : -1;
}

int wa_get_pubkey_by_webid(const uint8_t *webid, size_t webid_len, uint8_t *out, size_t cap) {
    int slot = wa_find_slot_by_webid(webid, webid_len);
    if (slot < 0) return -1;
    uint8_t priv[32];
    if (wa_load(slot, NULL, NULL, 0, NULL, 0, priv) != 0) return -1;
    int r = pubkey_from_priv(priv, out, cap);
    memset(priv, 0, sizeof(priv));
    return r;
}

int wa_sign_hash_by_webid(const uint8_t *webid, size_t webid_len,
                          const uint8_t hash[32], uint8_t *out, size_t cap) {
    int slot = wa_find_slot_by_webid(webid, webid_len);
    if (slot < 0) return -1;
    uint8_t id[WA_ID_LEN];
    if (wa_load(slot, id, NULL, 0, NULL, 0, NULL) != 0) return -1;
    return wa_sign_hash(id, hash, out, cap);
}

int wa_set_meta(const uint8_t id[WA_ID_LEN], const wa_meta_t *meta) {
    if (!id || !meta) return -1;
    if (!esp_crypto_unlocked()) return -1;
    int slot = wa_find_slot_by_id(id);
    if (slot < 0) return -1;

    /* 读出完整明文，替换 meta 段，再写回 */
    nvs_handle_t h;
    if (nvs_open(WA_NS, NVS_READONLY, &h) != ESP_OK) return -1;
    char k[8]; slot_key(slot, k, sizeof(k));
    uint8_t b[512]; size_t len = sizeof(b);
    esp_err_t err = nvs_get_blob(h, k, b, &len);
    nvs_close(h);
    if (err != ESP_OK) return -1;

    uint8_t plain[512];
    int pl = esp_crypto_decrypt(b, len, plain, sizeof(plain));
    if (pl < WA_PLAIN_LEN) { memset(plain, 0, sizeof(plain)); return -1; }

    meta_serialize(meta, plain + WA_META_OFF);

    uint8_t enc[WA_PLAIN_LEN + 32];
    int el = esp_crypto_encrypt(plain, WA_PLAIN_LEN, enc, sizeof(enc));
    memset(plain, 0, sizeof(plain));
    if (el <= 0) return -1;

    if (nvs_open(WA_NS, NVS_READWRITE, &h) != ESP_OK) return -1;
    err = nvs_set_blob(h, k, enc, el);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return (err == ESP_OK) ? 0 : -1;
}

int wa_sign(const uint8_t id[WA_ID_LEN],
            const uint8_t *data, size_t len,
            uint8_t *out, size_t cap) {
    if (!id || !data || !out || cap < 64) return -1;
    uint8_t hash[32];
    mbedtls_sha256(data, len, hash, 0);
    return wa_sign_hash(id, hash, out, cap);
}

int wa_sign_hash(const uint8_t id[WA_ID_LEN],
                 const uint8_t hash[32],
                 uint8_t *out, size_t cap) {
    if (!id || !hash || !out || cap < 64) return -1;
    if (!esp_crypto_unlocked()) return -1;
    if (ensure_rng() != 0) return -1;

    int slot = wa_find_slot_by_id(id);
    if (slot < 0) return -1;
    uint8_t priv[32];
    if (wa_load(slot, NULL, NULL, 0, NULL, 0, priv) != 0) return -1;

    /* 用独立的 group + mpi 签名（避免访问 mbedtls_ecp_keypair 的私有成员） */
    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    int rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (rc == 0) rc = mbedtls_mpi_read_binary(&d, priv, 32);
    if (rc == 0) {
        rc = mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, 32,
                                mbedtls_ctr_drbg_random, &s_drbg);
    }
    if (rc == 0) {
        size_t rl = mbedtls_mpi_size(&r), sl = mbedtls_mpi_size(&s);
        if (rl <= 32 && sl <= 32) {
            memset(out, 0, 64);
            mbedtls_mpi_write_binary(&r, out + (32 - rl), rl);
            mbedtls_mpi_write_binary(&s, out + 32 + (32 - sl), sl);
        } else {
            rc = -1;
        }
    }
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    memset(priv, 0, sizeof(priv));
    return (rc == 0) ? 64 : -1;
}

int wa_list(wa_emit_fn emit) {
    if (!emit || !esp_crypto_unlocked()) return -1;
    int n = 0;
    for (int i = 0; i < WA_MAX_CREDS; i++) {
        uint8_t id[WA_ID_LEN];
        char r[WA_MAX_RP], u[WA_MAX_USER];
        if (wa_load(i, id, r, sizeof(r), u, sizeof(u), NULL) != 0) continue;
        char hex[WA_ID_LEN * 2 + 1];
        for (int j = 0; j < WA_ID_LEN; j++) sprintf(hex + j * 2, "%02x", id[j]);
        hex[WA_ID_LEN * 2] = 0;
        char line[192];
        snprintf(line, sizeof(line), "%s\t%s\t%s\n", hex, r, u);
        emit(line);
        n++;
    }
    return n;
}

int wa_list_count(void) {
    if (!esp_crypto_unlocked()) return -1;
    nvs_handle_t h;
    if (nvs_open(WA_NS, NVS_READONLY, &h) != ESP_OK) return 0;
    int n = 0;
    for (int i = 0; i < WA_MAX_CREDS; i++) {
        char k[8]; slot_key(i, k, sizeof(k));
        size_t len = 0;
        if (nvs_get_blob(h, k, NULL, &len) == ESP_OK) n++;
    }
    nvs_close(h);
    return n;
}

int wa_delete(const uint8_t id[WA_ID_LEN]) {
    if (!id || !esp_crypto_unlocked()) return -1;
    int slot = wa_find_slot_by_id(id);
    if (slot < 0) return -1;
    nvs_handle_t h;
    if (nvs_open(WA_NS, NVS_READWRITE, &h) != ESP_OK) return -1;
    char k[8]; slot_key(slot, k, sizeof(k));
    esp_err_t err = nvs_erase_key(h, k);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return (err == ESP_OK) ? 0 : -1;
}

int wa_wipe(void) {
    nvs_handle_t h;
    if (nvs_open(WA_NS, NVS_READWRITE, &h) != ESP_OK) return -1;
    int cnt = 0;
    for (int i = 0; i < WA_MAX_CREDS; i++) {
        char k[8]; slot_key(i, k, sizeof(k));
        size_t len = 0;
        if (nvs_get_blob(h, k, NULL, &len) == ESP_OK) {
            if (nvs_erase_key(h, k) == ESP_OK) cnt++;
        }
    }
    nvs_commit(h);
    nvs_close(h);
    return cnt;
}
