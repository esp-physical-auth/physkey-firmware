/*
 * webauthn.h - 网络凭证（WebAuthn / FIDO2 风格的硬件认证器）ESP32 端实现
 *
 * 设计目标：
 *   让 ESP32 充当一个“私钥永不导出”的硬件认证器。每把凭证是一个 ECDSA
 *   P-256 密钥对（WebAuthn 标准曲线 secp256r1），私钥用密码派生的
 *   AES-256-GCM 主密钥加密后存 NVS；唯一能用到私钥的操作是“对数据签名”。
 *
 * 与标准 WebAuthn 的对应关系：
 *   注册（create） : 设备生成密钥对，返回公钥 + 凭证 ID（credential id）
 *   认证（get）    : 设备用私钥对“挑战”做 ECDSA/SHA-256 签名，返回 64 字节
 *                    raw (r||s)，网页用 WebCrypto 导入 JWK 公钥直接验签
 *
 * 私钥安全模型（与钱包模块一致）：
 *   - 私钥密文存 NVS，明文只在签名瞬间短暂出现在栈上，用完立即清零
 *   - 没有“读取私钥”的接口——只能签名
 *   - 所有操作要求已解锁（先 AUTHPASS）
 */
#ifndef WEBAUTHN_H
#define WEBAUTHN_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WA_MAX_CREDS   8     /* 最多同时保存的凭证数 */
#define WA_ID_LEN      16    /* 凭证 ID 长度（随机字节） */
#define WA_MAX_RP      64    /* 域名/RP 名的最大长度 */
#define WA_MAX_USER    64    /* 用户名（展示用）最大长度 */
#define WA_MAX_UID     64    /* user handle（浏览器给的 user id）最大长度 */
#define WA_MAX_DISPLAY 64    /* user display name 最大长度 */
#define WA_MAX_WEBID   32    /* soft-fido2 对外 credential id 最大长度（一般 32 字节）*/

/* 凭证元数据（存 NVS，随 id/rp/user/priv 一同 AES-GCM 加密）*/
typedef struct {
    int64_t  created;        /* 创建时间（Unix 时间戳）*/
    uint32_t sign_count;     /* 签名计数器 */
    int32_t  alg;            /* COSE 算法（-7 = ES256）*/
    uint8_t  cred_protect;   /* credProtect 级别 */
    uint8_t  discoverable;   /* 是否常驻凭证（rk）*/
    uint8_t  backup_state;   /* CredentialBackupState 原始值 */
    uint8_t  user_id_len;    /* 下面 user_id 的有效字节数 */
    uint8_t  user_id[WA_MAX_UID];
    uint8_t  user_display_len;
    uint8_t  user_display[WA_MAX_DISPLAY];
    uint8_t  web_id_len;     /* 对外 credential id（soft-fido2 的）长度 */
    uint8_t  web_id[WA_MAX_WEBID];
} wa_meta_t;

/*
 * 注册一把新凭证：
 *   生成 P-256 密钥对，随机分配 credential_id，公钥与 rp/user 一起存 NVS。
 *   - rp   : 依赖方标识（例如 "gitea.example.com"），不能为空
 *   - user : 展示用用户名（可为空字符串）
 *   - id_out : 输出 WA_ID_LEN 字节的凭证 ID
 * 返回 0 成功；-1 已锁定 / 参数非法 / 空间满。
 *
 * 注：注册时元数据用默认值（created=0、alg=-7、discoverable=1 等），
 *     上层应随后调用 wa_set_meta() 写入浏览器要求的完整元数据。
 */
int wa_register(const char *rp, const char *user,
                uint8_t id_out[WA_ID_LEN]);

/*
 * 按 rp（+ 可选 user 匹配）查找已有凭证，命中则返回其 ID。
 * 用于“注册前先看有没有现成凭证”的去重场景。
 * 返回 0 命中，-1 未找到或未解锁。
 */
int wa_find_credential(const char *rp, const char *user,
                       uint8_t id_out[WA_ID_LEN]);

/*
 * 取某把凭证的公钥（未压缩点，65 字节）。返回 65 或 -1。
 * 网页用它构造 JWK 来验签。
 */
int wa_get_pubkey(const uint8_t id[WA_ID_LEN], uint8_t *out, size_t cap);

/*
 * 取某把凭证的 rp / user（供网页确认“这是哪个网站的凭证”）。
 * 任一出参可为 NULL。返回 0 成功。
 */
int wa_get_meta(const uint8_t id[WA_ID_LEN],
                char *rp_out, size_t rp_cap,
                char *user_out, size_t user_cap);

/*
 * 取某把凭证的完整元数据（created/sign_count/alg/cred_protect/
 * discoverable/backup_state/user_id/user_display）。
 * 返回 0 成功，-1 未找到/未解锁。
 */
int wa_get_meta_full(const uint8_t id[WA_ID_LEN], wa_meta_t *out);

/*
 * 写入/更新某把凭证的完整元数据（注册后由上层补齐浏览器要求的信息）。
 * 返回 0 成功。
 */
int wa_set_meta(const uint8_t id[WA_ID_LEN], const wa_meta_t *meta);

/*
 * 认证（断言）：用指定凭证的私钥对 data 做 ECDSA/SHA-256 签名。
 *   data : 待签内容（通常 = 拼接后的 authenticatorData || SHA256(clientDataJSON)，
 *          由上层/网页决定，设备只负责“对给到的字节签名”）
 *   out  : 输出 64 字节 raw (r||s)
 * 返回 64 或 -1（未解锁 / 找不到凭证 / 签名失败）。
 */
int wa_sign(const uint8_t id[WA_ID_LEN],
            const uint8_t *data, size_t len,
            uint8_t *out, size_t cap);

/*
 * 与 wa_sign 相同，但 data 已经是 32 字节 SHA-256 摘要，本函数不再二次哈希，
 * 直接用私钥对给定摘要做 ECDSA 签名。
 * 供 CTAP2/WebAuthn 桥使用：上层（PC 端）已把 authenticatorData||clientDataHash
 * 算好 SHA-256，设备只负责对摘要签名。
 *   hash : 32 字节待签摘要
 *   out  : 输出 64 字节 raw (r||s)
 * 返回 64 或 -1。
 */
int wa_sign_hash(const uint8_t id[WA_ID_LEN],
                 const uint8_t hash[32],
                 uint8_t *out, size_t cap);

/*
 * 列出全部凭证（供网页显示/管理）。
 * 每个条目调用 emit.callback(line)，line 为：
 *   ID_HEX(32) \t RP \t USER
 * 返回导出的数量。
 */
typedef void (*wa_emit_fn)(const char *line);
int wa_list(wa_emit_fn emit);

/* 仅返回当前凭证数量（不解密/不输出内容），供快速统计。 */
int wa_list_count(void);

/* 删除一把凭证。返回 0 成功，-1 不存在 / 未解锁。 */
int wa_delete(const uint8_t id[WA_ID_LEN]);

/* 清空全部凭证，返回删除的数量。 */
int wa_wipe(void);

/* ---- 按对外 web credential id（soft-fido2 的 cred.id）操作 ----
 * passless 的 storage 读写都以 credential.id 为键，而 ESP32 内部用的是
 * 16 字节 id；WA_SETMETA 时会把 web_id 一起存下，下列函数按 web_id 定位。*/
int wa_get_meta_by_webid(const uint8_t *webid, size_t webid_len,
                         char *rp_out, size_t rp_cap,
                         char *user_out, size_t user_cap,
                         wa_meta_t *meta_out);
int wa_delete_by_webid(const uint8_t *webid, size_t webid_len);
int wa_get_pubkey_by_webid(const uint8_t *webid, size_t webid_len, uint8_t *out, size_t cap);

/* 更新某把凭证（按内部 id）的 rp / user 字段。NULL 表示不变。返回 0 成功。 */
int wa_update_rp_user(const uint8_t id[WA_ID_LEN], const char *rp, const char *user);
int wa_sign_hash_by_webid(const uint8_t *webid, size_t webid_len,
                          const uint8_t hash[32], uint8_t *out, size_t cap);

/* 按【对外 web credential id】定位并取出内部 id + 完整元数据。
 * 用于 WA_SETMETA_WEB（从 storage 读回后再写元数据）。返回 0 成功。 */
int wa_get_id_meta_by_webid(const uint8_t *webid, size_t webid_len,
                            uint8_t id_out[WA_ID_LEN], wa_meta_t *meta_out);

#ifdef __cplusplus
}
#endif
#endif /* WEBAUTHN_H */
