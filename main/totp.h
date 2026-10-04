#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 将 Base32 字符串解码为原始字节。
 * 兼容大小写、忽略空格和 '-'、可选尾部 '=' 填充。
 *
 * @param in      输入的 Base32 字符串（以 '\0' 结尾）
 * @param out     输出缓冲区
 * @param out_len 输出缓冲区大小
 * @return 解码后的字节数；失败返回 -1
 */
int totp_base32_decode(const char *in, uint8_t *out, size_t out_len);

/**
 * 计算 TOTP (RFC 6238) 6 位验证码。
 *
 * @param key        Base32 编码的密钥
 * @param digits     数字位数（通常为 6，最大 9）
 * @param period     时间步长秒数（通常为 30）
 * @param timestamp  Unix 时间戳（秒）
 * @return 计算得到的验证码数值；失败返回 -1
 */
int totp_generate(const char *key, int digits, int period, uint64_t timestamp);

/**
 * 计算 TOTP 并格式化为字符串（左补零）。
 *
 * @param key       Base32 编码的密钥
 * @param digits    数字位数
 * @param period    时间步长秒数
 * @param timestamp Unix 时间戳（秒）
 * @param out       输出字符串缓冲区（至少 digits+1 字节）
 * @return 0 成功；-1 失败
 */
int totp_generate_str(const char *key, int digits, int period,
                      uint64_t timestamp, char *out);

/**
 * 计算 Steam Guard 令牌验证码（5 位，字符表 23456789BCDFGHJKMNPQRTVWXY）。
 * Steam 的 shared_secret 是 base64 编码（不是 base32）。
 *
 * @param shared_secret_b64  Base64 编码的 shared_secret
 * @param timestamp          Unix 时间戳（秒）
 * @param out                输出字符串缓冲区（至少 6 字节，写入 5 字符 + '\0'）
 * @return 0 成功；-1 失败
 */
int steam_generate_str(const char *shared_secret_b64, uint64_t timestamp, char *out);

/**
 * 计算 Steam 验证码（返回 5 个字符写入 out，不含 '\0' 时的数值版本不适用）。
 * 与 steam_generate_str 相同，保留以便扩展。
 */
int steam_generate(const char *shared_secret_b64, uint64_t timestamp, char out[6]);

#ifdef __cplusplus
}
#endif
