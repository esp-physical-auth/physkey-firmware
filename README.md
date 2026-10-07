# ESP32 硬件安全认证器 🦀

基于 **ESP32** 的多功能硬件认证器，集成 **TOTP 两步验证**、**WebAuthn/FIDO2 凭证**、**ECDSA 钱包私钥** 和 **设备身份证书**。手机或 PC 通过 **BLE（NUS 服务）** 连接后即可远程管理，密钥永不出芯片。

> 设备广播名：`ATRI-TOTP`

---

## 功能一览

| 模块 | 说明 |
|------|------|
| 🔢 TOTP | 标准 RFC 6238 / Google Authenticator 兼容，支持 Steam Guard，密钥存 NVS |
| 🔐 WebAuthn | FIDO2 风格的硬件凭证——ECDSA P-256 私钥永不导出，只暴露签名能力 |
| 💰 钱包 | BIP32 风格的 secp256k1 私钥存储与签名，标签管理，只进不出 |
| 🪪 设备身份 | ECDSA P-256 密钥对 + 本地 CA 签发证书，私钥永不出芯片 |
| 🔒 密码保护 | PBKDF2 派生主密钥，AES-256-GCM 加密所有敏感数据 |
| 🛡️ Secure Boot V2 | 完整的签名 + Flash AES-XTS 加密烧录流程 |
| ⏰ 时间同步 | Wi-Fi + SNTP 自动授时（TOTP 依赖） |

---

## 硬件要求

- **ESP32** 开发板（其他支持 BLE 的 ESP32 变体亦可）
- USB 数据线
- **ESP-IDF v5.4+**（ESP32 正式支持从 5.4 开始）

---

## 目录结构

```
esp32c5-totp/
├── CMakeLists.txt              顶层工程（目标芯片 esp32c5）
├── partitions.csv              自定义分区表（4MB Flash，app 分区 0x20000 起）
├── sdkconfig.defaults          默认配置（NimBLE / Wi-Fi / mbedTLS SHA1）
├── flash-secure.sh             一键签名 + AES-XTS 加密 + 烧录脚本
├── bt_connectivity_test.py     BLE 连通性测试（WebAuthn 桥验证）
├── main/
│   ├── main.c                  app_main 入口：NVS 初始化 → SNTP → BLE → Console
│   ├── ble_totp.c / .h         BLE NUS 服务 + 命令解析器（支持所有模块的指令）
│   ├── totp.c / .h             TOTP 核心算法（Base32 解码 + HMAC-SHA1）
│   ├── storage.c / .h          NVS 持久化（TOTP / WebAuthn / 钱包 / 证书）
│   ├── crypto.c / .h           设备身份、密码派生、AES-256-GCM、钱包签名
│   ├── webauthn.c / .h         WebAuthn/FIDO2 凭证注册与 ECDSA 签名
│   └── CMakeLists.txt
├── tools/
│   ├── atri-ca.py              本地 CA：给设备公钥签发证书
│   ├── test_trustchain.py      信任链验证脚本
│   ├── check_auth.py           认证辅助
│   ├── save_authdata.py        保存认证数据
│   ├── debug_webcrypto.js      WebCrypto 调试
│   └── ca/                     CA 私钥与签发产物（已在 .gitignore 中排除）
└── secure_boot/                签名密钥 + Flash 加密密钥 + 构建产物（已排除）
```

---

## 编译与烧录

### 普通编译（未启用 Secure Boot / Flash 加密）

```bash
# 1. 导出 IDF 环境
. $HOME/esp/esp-idf/export.sh

# 2. 设置目标芯片
idf.py set-target esp32c5

# 3. 可选：修改 Wi-Fi 账号密码用于 SNTP 授时
#    编辑 main/main.c 中的 WIFI_SSID / WIFI_PASSWORD / ENABLE_SNTP

# 4. 编译烧录
idf.py build flash monitor
```

如串口未自动识别，加 `-p /dev/ttyUSB0`（或 `ttyACM0`）。

### 安全烧录（Secure Boot V2 + Flash AES-XTS 加密）

项目已包含完整的一键脚本 `flash-secure.sh`，自动完成 **备份 → 编译 → 签名 → AES-XTS 加密 → 烧录**。

```bash
# 准备工作（首次）：
#   1. 生成签名密钥：espsecure.py generate_signing_key --version 2 secure_boot/secure_boot_signing_key.pem
#   2. 生成 Flash 加密密钥：espsecure.py generate_flash_encryption_key secure_boot/flash_enc_key.bin
#   3. 在芯片 eFuse 中启用 Secure Boot V2 和 Flash 加密（一次性，不可逆！）

# 日常烧录（默认只烧 app，安全）
./flash-secure.sh

# 指定串口
./flash-secure.sh /dev/ttyACM0

# 全量烧录（bootloader + 分区表 + app，有风险，需 eFuse 已开放写保护）
./flash-secure.sh --full
```

> ⚠️ **血的教训**：ESP32 使用 **AES-XTS** 加密，加密时必须加 `--aes_xts` 参数。地址必须与 `partitions.csv` 对齐——app 分区从 `0x20000` 起（不是 `0x10000`），地址写错会导致固件永远启动不了。详见脚本内注释。

---

## BLE 指令集

设备通过 **Nordic UART Service (NUS)** 暴露命令接口，任何支持 BLE 透传的 App 都能连（推荐 **nRF Connect**）。连接后：

- **RX 特征**（`6e400002-...`）→ 写入命令（UTF-8，`\n` 结尾）
- **TX 特征**（`6e400003-...`）→ 开启 Notify 接收响应

### 通用 / 密码

| 指令 | 说明 |
|------|------|
| `HASPASS` | 查询是否已设置密码 |
| `SETPASS <密码>` | 首次设置密码（8 字符以上） |
| `AUTHPASS <密码>` | 解锁（所有敏感操作前必须先解锁） |
| `CHGPASS <旧> <新>` | 修改密码 |
| `LOCK` | 手动锁定（清除内存主密钥） |

### TOTP（需先解锁）

| 指令 | 说明 |
|------|------|
| `ADD <名字> <Base32密钥> [位数] [周期]` | 新增/覆盖密钥 |
| `DEL <名字>` | 删除密钥 |
| `LIST` | 列出所有账号 |
| `GET <名字>` | 获取当前 6 位验证码（含剩余有效秒数） |

### WebAuthn（需先解锁）

| 指令 | 说明 |
|------|------|
| `WA_REG <RP> <用户>` | 注册新凭证，返回 credential ID + 公钥 |
| `WA_PUB <cred_id>` | 查询凭证公钥 |
| `WA_SIGNHASH <cred_id> <base64摘要>` | 对 32 字节 SHA-256 摘要做 ECDSA 签名（返回 64 字节 raw r\|\|s） |
| `WA_LIST` | 列出全部凭证 |
| `WA_DEL <cred_id>` | 删除凭证 |

### 钱包（需先解锁）

| 指令 | 说明 |
|------|------|
| `WALLET_IMPORT <标签> <hex私钥>` | 导入 secp256k1 私钥（只进不出） |
| `WALLET_LIST` | 列出钱包标签（绝不暴露私钥） |
| `WALLET_SIGNHASH <标签> <base64摘要>` | 对 32 字节哈希做 secp256k1 ECDSA 签名 |
| `WALLET_PUB <标签>` | 获取压缩公钥（33 字节） |
| `WALLET_DEL <标签>` | 删除一把密钥 |

### 设备身份 / CA

| 指令 | 说明 |
|------|------|
| `ID_PUB` | 打印设备公钥（供 CA 签名） |
| `ID_FP` | 打印设备公钥 SHA-256 指纹（用于人工核对） |
| `GETCERT` | 读取已安装证书链（两段：`设备证书\|中间CA证书`；单段时仅设备证书） |
| `SETCERT <base64 DER>[\|<中间CA证书b64>]` | 安装证书链：仅设备证书，或“设备证书+中间CA证书”两段 |
| `AUTH <base64 nonce>` | 挑战-响应：用设备私钥签名随机数（返回 `SIG:<base64>`） |
| `WHOAMI` | 打印设备身份概览（公钥/指纹/证书状态） |

### 其他

| 指令 | 说明 |
|------|------|
| `HELP` | 显示帮助 |
| `TIME <unix时间戳>` | 手动校准时间（不依赖 SNTP 时可用） |

---

## 本地 CA 证书签发流程

设备身份模块实现一套 **SSL/TLS 式三级证书链**：

```
根 CA（root，离线） ──签──▶ 中间 CA 证书（0x10） ──签──▶ 设备证书（0x02）
客户端只内置【根 CA 公钥】，验签全程离线（不写网、不写死域名/IP）
```

设备端只需做两件事：**导出公钥** 和 **安装证书链**；签发全在 PC / 官方工具完成。

### ① 设备端：导出公钥

设备上电，经 BLE 发送：

```
WHOAMI        # 概览（含公钥/指纹/证书状态）
ID_PUB        # 只取设备公钥（hex，65 字节，04 开头，130 字符）
```

用 nRF Connect、web 页或 passless 均可发送。

### ② PC 端：签发证书链（`tools/atri-ca.py`）

```bash
cd tools

# （一次性）生成中间 CA 密钥对
python3 atri-ca.py uca-init

# 用官方工具签发中间 CA 证证书（推荐）：
#   打开 https://esp.oleanderchat.asia/ ，填 deployment_id + 中间CA公钥，点签发
#   把返回的证书保存为 ca/uca_cert.b64
#   （也可本地离线签发：python3 atri-ca.py root-sign-uca "$(python3 atri-ca.py uca-pub)" <deployment_id>）

# 用中间 CA 给设备签证书，并拼成两段链
UCACERT=$(cat ca/uca_cert.b64)
python3 atri-ca.py uca-sign <设备公钥hex> <deployment_id> "$UCACERT"
# → 打印：SETCERT <设备证书>|<中间CA证书>
```

### ③ 设备端：安装证书链

把上一步打印的整条 `SETCERT <设备证书>|<中间CA证书>` 经 BLE 发送给设备。
固件分段存入 NVS（设备证书 1 段 + 中间 CA 证书 1 段）。

```
SETCERT <base64(设备证书)>|<base64(中间CA证书)>
```

### ④ 验证

```
GETCERT       # 应返回两段：OK CERT:<设备证书>|<中间CA证书>
```

然后网页端（内置根 CA 公钥）或 app 连上设备，会自动验完整条三级链并弹窗展示
**deployment_id**，确认设备归属。

> 📐 **deployment_id（部署标识）**：由你自定（如 `lianyu-tianhai`），签发时内嵌进证书。
> 客户端验签后展示给用户确认“这是我自己部署的设备”，并可在签发器端防抢注。
> 详见顶层 [`../README.md`](../README.md#命名)。
>
> 🌐 网页端：**https://esp.oleanderchat.asia/**

---

## 安全模型

### 密钥存储

| 密钥类型 | 存储方式 | 是否可导出 |
|----------|----------|-----------|
| TOTP Base32 密钥 | NVS（**明文**，生产环境建议开启 NVS 加密） | 通过 BLE 命令间接暴露 |
| WebAuthn 私钥 | NVS，AES-256-GCM 加密（主密钥由密码派生） | ❌ 永不，只暴露签名 |
| 钱包私钥 | NVS，AES-256-GCM 加密 | ❌ 永不，只暴露签名 |
| 设备身份私钥 | NVS，AES-256-GCM 加密 | ❌ 永不，只暴露签名 |
| Secure Boot 签名密钥 | `secure_boot/` 本地文件 | **务必备份后删除仓库** |
| Flash 加密密钥 | `secure_boot/` 本地文件 + eFuse | **务必备份后删除仓库** |

### 密码派生

使用 PBKDF2-HMAC-SHA256，随机盐（存 NVS），主密钥派生后缓存在 RAM 中——`LOCK` 或掉电即清除。

### 通信安全

BLE NUS 服务**未启用配对/绑定**，任何附近设备都能连接。敏感场景建议在 `sdkconfig.defaults` 中启用 `CONFIG_BT_NIMBLE_ENABLE_SM=y` 并实现 `ble_sm` 配对流程。

---

## 分区表

```
# partitions.csv
nvs,       data, nvs,    0xa000,   0x6000    # TOTP / WebAuthn / 钱包 / 证书存储
phy_init,  data, phy,    0x10000,  0x1000
factory,   app,  factory, 0x20000,  0x1f0000  # app 约 2MB（4MB Flash 剩余空间）
```

bootloader 在 `0x2000`，分区表在 `0x9000`，app 在 `0x20000`。Flash 加密地址参数**必须与此一致**。

---

## 依赖

- **ESP-IDF v5.4+**
- **NimBLE**（ESP32 推荐的 BLE 协议栈，sdkconfig.defaults 已配好）
- **mbedTLS**（硬件加速 SHA1 / SHA256 / ECDSA / AES-GCM）
- **Bleak**（Python BLE 客户端，用于测试脚本，`.venv/` 已包含）

---

## 常见问题

**Q: TOTP 验证码不准？**
A: TOTP 严格依赖 Unix 时间。ESP32 无 RTC 电池，断电后时间丢失。开启 `ENABLE_SNTP=1` 并填入 Wi-Fi 密码，或手动发送 `TIME` 指令校准。

**Q: 为什么 WebAuthn / 钱包命令返回 ERR locked？**
A: 敏感模块需要先解锁——发送 `AUTHPASS <密码>`（或 `SETPASS` 首次设置）成功后才能操作，`LOCK` 或重启后需重新解锁。

**Q: Secure Boot / Flash 加密开了之后能关掉吗？**
A: **不能。** eFuse 操作不可逆。启用前务必备份好所有密钥文件和当前固件镜像。

**Q: `flash-secure.sh` 报错地址不匹配？**
A: 脚本中的 `ADDR_APP`、`ADDR_BOOTLOADER`、`ADDR_PARTITION` 三个常量必须和 `partitions.csv` 完全对齐。脚本在第 5 步会自动校验，不一致会直接退出。

---

## 许可证

本项目基于 **GNU General Public License v3.0** 开源，详见 [`LICENSE`](./LICENSE) 文件。

> ⚠️ 请注意：ESP-IDF 本身采用 Apache License v2.0，mbedTLS 采用 Apache License v2.0，本项目代码的 GPLv3 仅适用于项目自有部分。如果你计划发布修改后的版本，请确保理解 GPLv3 的传染性与加密固件分发相关条款。
