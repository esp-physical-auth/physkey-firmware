/*
 * crypto.h - 设备身份与加密通讯（HTTPS/CA 信任链模型的 ESP 端实现）
 *
 * 角色对应：
 *   电脑 = CA（持有 CA 私钥，签发设备证书）
 *   ESP32 = 服务器（持有设备私钥，出示证书；私钥永不出芯片）
 *   网页 = 浏览器（内置 CA 公钥，验签设备证书）
 *
 * 信任链：
 *   1. ESP 启动时若无设备密钥对 -> 生成 ECDSA P-256（secp256r1）密钥对
 *   2. 串口打印设备公钥，供电脑 CA 签名
 *   3. 电脑用 CA 私钥给设备公钥签发证书 -> SETCERT 写回 ESP 保存
 *   4. 网页连接时发起挑战，ESP 用设备私钥对随机数签名 -> 网页用 CA 公钥验签证书 + 验签名
 */
#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

/* 初始化：从 NVS 加载或生成设备密钥对；打印公钥供 CA 签名 */
esp_err_t espid_init(void);

/* 是否已有设备密钥对 */
bool espid_has_key(void);

/* 是否已安装 CA 签发的证书 */
bool espid_has_cert(void);

/* 获取设备公钥（未压缩点格式，65 字节：0x04||X||Y）。返回实际长度，-1 失败 */
int espid_get_pubkey(uint8_t *out, size_t cap);

/* 获取设备公钥的指纹（SHA-256，32 字节），可用于人工核对 */
int espid_get_pubkey_fingerprint(uint8_t out[32]);

/* 用设备私钥对数据做 ECDSA P-256 + SHA-256 签名（DER 编码输出） */
int espid_sign(const uint8_t *data, size_t len, uint8_t *sig_out, size_t cap);

/* 保存 CA 签发的设备证书（base64 或原始 DER 由上层决定，这里存原始字节） */
esp_err_t espid_set_cert(const uint8_t *der, size_t len);

/* 读取设备证书 */
int espid_get_cert(uint8_t *out, size_t cap);

/* ---- 两级 CA 链：用户 CA 证书 ---- */
/* 保存“用户 CA 证书”（由根 CA 签发；设备证书由用户 CA 签发）。 */
esp_err_t espid_set_user_ca_cert(const uint8_t *der, size_t len);
/* 读取用户 CA 证书；未安装返回 -1。 */
int espid_get_user_ca_cert(uint8_t *out, size_t cap);
/* 是否已安装用户 CA 证书。 */
bool espid_has_user_ca_cert(void);

/* ---- 密码保护 ---- */
/* 是否已设置密码 */
bool esp_pass_is_set(void);
/* 设置密码（首次）或校验（后续）。存储为 盐+PBKDF2/HMAC 派生值 */
esp_err_t esp_pass_set(const char *password);
bool esp_pass_verify(const char *password);
/* 重置密码（需已通过验证，调用方负责先验旧密码） */
esp_err_t esp_pass_reset(const char *new_password);

/* ---- 数据加密（AES-256-GCM，密钥由密码派生） ---- */
/* 是否已解锁（主密钥已在内存中） */
bool esp_crypto_unlocked(void);
/* 锁定：清除内存中的主密钥 */
void esp_crypto_lock(void);
/*
 * 用密码派生主密钥并缓存到内存（验密码成功后调用）。
 * 返回 0 成功；-1 密码错误。
 */
int esp_crypto_unlock(const char *password);
/*
 * AES-256-GCM 加密：
 *   out 格式 = nonce(12) || ciphertext(len) || tag(16)
 *   返回输出总字节数，失败返回 -1。out 至少需 len+28 字节。
 */
int esp_crypto_encrypt(const uint8_t *in, size_t len, uint8_t *out, size_t cap);
/*
 * AES-256-GCM 解密：
 *   in 格式 = nonce(12) || ciphertext || tag(16)
 *   返回明文字节数，失败返回 -1。
 */
int esp_crypto_decrypt(const uint8_t *in, size_t len, uint8_t *out, size_t cap);

/* ---- 钱包私钥（只进不出，永不可能导出） ----
 *
 * 每把密钥用AES-256-GCM 加密后存 NVS。
 * 没有“读取私钥”的接口——只能签名。
 * 支持 secp256k1（BTC）。
 */
#define WALLET_MAX_KEYS 8
#define WALLET_MAX_NAME 32

/* 新增/覆盖一把私钥（须已解锁）。priv 为 32 字节 secp256k1 私钥，label 为标签。 */
esp_err_t wallet_import(const char *label, const uint8_t priv[32]);
/* 列出钱包密钥的标签（只返回名字，绝不返回私钥）。name 为 ';' 分隔。 */
int wallet_list(char *buf, size_t cap);
/* 删除一把钱包密钥。返回0成功。 */
int wallet_del(const char *label);
/* 清除全部钱包密钥，返回数量。 */
int wallet_wipe(void);
/* 用指定标签的私钥对 32 字节哈希做 ECDSA(secp256k1) 签名。
 * out 为 64 字节 raw(r||s)，返回 64 或 -1。 */
int wallet_sign_hash(const char *label, const uint8_t hash32[32], uint8_t *out, size_t cap);
/* 取某把密钥对应的压缩公钥（33 字节），返回 33 或 -1。 */
int wallet_get_pubkey(const char *label, uint8_t *out, size_t cap);

#endif /* CRYPTO_H */
