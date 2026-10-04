#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TOTP_MAX_NAME   32  /* 账号名最大长度 */
#define TOTP_MAX_SECRET 128 /* Base32 密钥最大长度 */
#define TOTP_MAX_ENTRIES 32 /* 最多存储条目数 */

typedef struct {
    char name[TOTP_MAX_NAME];     /* 账号名，作为唯一键 */
    char secret[TOTP_MAX_SECRET]; /* Base32 密钥（标准 TOTP）；Steam 时存 base64 shared_secret */
    uint8_t digits;               /* 位数，默认 6 */
    uint16_t period;              /* 时间步长秒，默认 30 */
    uint8_t type;                 /* 0 = 标准 TOTP；1 = Steam Guard */
} totp_entry_t;

#define TOTP_TYPE_STANDARD 0
#define TOTP_TYPE_STEAM    1

/** 初始化 NVS 存储。返回 0 成功。 */
int totp_store_init(void);

/** 增加 / 覆盖一个条目。返回 0 成功。 */
int totp_store_add(const char *name, const char *secret, uint8_t digits, uint16_t period);

/** 带类型（标准 TOTP / Steam）的新增/覆盖。 */
int totp_store_add_typed(const char *name, const char *secret, uint8_t digits,
                         uint16_t period, uint8_t type);

/** 删除一个条目。返回 0 成功，-1 不存在。 */
int totp_store_del(const char *name);
int totp_store_wipe(void);

/** 读取一个条目。返回 0 成功，-1 不存在。 */
int totp_store_get(const char *name, totp_entry_t *out);

/**
 * 列出所有条目名。names 为输出缓冲区，每条写入 '\0' 结尾的原始行，
 * cap 为缓冲区总大小。返回写入的条目数量。
 */
int totp_store_list(char *buf, size_t cap);

/** 返回当前存储的条目数量。 */
int totp_store_count(void);

/**
 * 导出全部条目。对每个条目调用 emit.callback(line)，line 为：
 *   name\tsecret\ttype\tdigits\tperiod
 * 返回导出的条目数。
 */
typedef void (*totp_emit_fn)(const char *line);
int totp_store_dump_all(totp_emit_fn emit);

#ifdef __cplusplus
}
#endif
