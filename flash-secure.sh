#!/usr/bin/env bash
# flash-secure.sh — ESP32 安全固件一键烧录脚本
#
# 适用：已启用 Flash 加密 + Secure Boot V2 的 ESP32
# 自动完成：备份 → 编译 → 签名 → AES-XTS 加密 → 烧录
#
# ★ 关键避坑（血的教训）★
#   1. ESP32 用 AES-XTS 加密，加密时必须加 --aes_xts，否则启动失败！
#   2. ★★ 地址必须和 partitions.csv 对齐 ★★
#        分区表分区布局（本工程 partitions.csv）：
#          bootloader : 0x2000
#          partition  : 0x9000
#          app(factory): 0x20000   <-- 注意！不是 0x10000
#      --address 参数会混入 AES-XTS 密钥派生，地址写错 -> 固件永远启动不了。
#      旧脚本写死 0x10000 就是错的，烧出来必然启动失败。
#   3. eFuse 操作不可逆，密钥务必备份！
#   4. Secure Boot 开启后，flash < 0x8000 的区域禁止写入（bootloader 受保护），
#      因此本脚本默认【只烧 app】。需要刷 bootloader/分区表时用 --full（危险，慎用）。
#
# 用法:
#   ./flash-secure.sh              # 编译+签名+加密+烧 app（默认，安全）
#   ./flash-secure.sh /dev/ttyACM0 # 指定串口
#   ./flash-secure.sh --full       # 连 bootloader+分区表一起烧（有风险）
set -e

# ---------------- 配置 ----------------
PROJ_DIR="$(cd "$(dirname "$0")" && pwd)"
export IDF_PATH="${IDF_PATH:-$HOME/esp/esp-idf}"
export IDF_PYTHON_ENV_PATH="${IDF_PYTHON_ENV_PATH:-$HOME/.espressif/python_env/idf5.5_py3.14_env}"
source "$IDF_PATH/export.sh" >/dev/null 2>&1

SB_DIR="$PROJ_DIR/secure_boot"
SIGN_KEY="$SB_DIR/secure_boot_signing_key.pem"
ENC_KEY="$SB_DIR/flash_enc_key.bin"
OUT_DIR="$SB_DIR/encrypted"
BK_ROOT="$SB_DIR/backups"

# ★ 地址常量：必须与 partitions.csv 保持一致 ★
ADDR_BOOTLOADER=0x2000
ADDR_PARTITION=0x9000
ADDR_APP=0x20000

# ---------------- 参数解析 ----------------
FULL=0
PORT=""
for arg in "$@"; do
    case "$arg" in
        --full) FULL=1 ;;
        *)      PORT="$arg" ;;
    esac
done
PORT="${PORT:-/dev/ttyACM0}"

# ---------------- [1/6] 备份现有固件 ----------------
echo "=== [1/6] 备份现有固件 ==="
BK="$BK_ROOT/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BK"
# 备份当前构建产物（若存在）
[ -f build/esp32c5-totp.bin ] && cp build/esp32c5-totp.bin "$BK/app-plain.bin" || true
[ -f build/bootloader/bootloader.bin ] && \
    cp build/bootloader/bootloader.bin "$BK/bootloader-plain.bin" || true
[ -f build/partition_table/partition-table.bin ] && \
    cp build/partition_table/partition-table.bin "$BK/partition-table-plain.bin" || true
# 备份上次成功烧录的加密镜像（若存在）——这才是真正的“当前运行固件”
[ -f "$OUT_DIR/app-enc.bin" ] && cp "$OUT_DIR/app-enc.bin" "$BK/prev-app-enc.bin" || true
# 备份关键配置
[ -f partitions.csv ] && cp partitions.csv "$BK/partitions.csv" || true
[ -f sdkconfig ] && cp sdkconfig "$BK/sdkconfig" || true
echo "备份完成 -> $BK"

# ---------------- [2/6] 编译 ----------------
echo "=== [2/6] 编译 ==="
cd "$PROJ_DIR"
idf.py --preview build

# ---------------- [3/6] 签名 app ----------------
echo "=== [3/6] 签名 app 固件 ==="
mkdir -p "$OUT_DIR"
espsecure.py sign_data --version 2 --keyfile "$SIGN_KEY" \
    --output "$OUT_DIR/app-signed.bin" build/esp32c5-totp.bin

# ---------------- [4/6] AES-XTS 加密 ----------------
echo "=== [4/6] AES-XTS 加密（★地址必须与 partitions.csv 对齐★） ==="
espsecure.py encrypt_flash_data --aes_xts --keyfile "$ENC_KEY" \
    --address "$ADDR_BOOTLOADER" --output "$OUT_DIR/bootloader-enc.bin" \
    build/bootloader/bootloader.bin
espsecure.py encrypt_flash_data --aes_xts --keyfile "$ENC_KEY" \
    --address "$ADDR_PARTITION" --output "$OUT_DIR/partition-enc.bin" \
    build/partition_table/partition-table.bin
# ★ app 地址 = 0x20000（不是 0x10000！）
espsecure.py encrypt_flash_data --aes_xts --keyfile "$ENC_KEY" \
    --address "$ADDR_APP" --output "$OUT_DIR/app-enc.bin" "$OUT_DIR/app-signed.bin"

# ---------------- [5/6] 校验地址 ----------------
echo "=== [5/6] 校验分区地址与常量一致 ==="
CSV_APP_ADDR=$(awk -F, '/factory/ && /app/ {gsub(/ /,"",$4); print $4}' partitions.csv)
CSV_PART_ADDR=$(awk -F, '/partition|Partition|^[[:space:]]*[a-zA-Z]/ {next}' partitions.csv || true)
echo "partitions.csv 中 factory app 偏移 = $CSV_APP_ADDR (脚本用 0x$(printf '%x' $ADDR_APP))"
if [ -n "$CSV_APP_ADDR" ] && [ "$((CSV_APP_ADDR))" != "$((ADDR_APP))" ]; then
    echo "!!! 警告：partitions.csv 中 app 偏移 ($CSV_APP_ADDR) 与脚本 ADDR_APP ($ADDR_APP) 不一致！" >&2
    echo "!!! 请修改脚本开头的 ADDR_APP 常量后再烧录。" >&2
    exit 1
fi

# ---------------- [6/6] 烧录 ----------------
echo "=== [6/6] 烧录到 $PORT ==="
if [ "$FULL" -eq 1 ]; then
    echo ">>> --full 模式：烧 bootloader + 分区表 + app（有风险）"
    esptool.py -p "$PORT" -b 460800 --chip esp32c5 \
        write_flash --flash_mode dio --flash_freq 80m --flash_size 4MB \
        $ADDR_BOOTLOADER "$OUT_DIR/bootloader-enc.bin" \
        $ADDR_PARTITION  "$OUT_DIR/partition-enc.bin" \
        $ADDR_APP        "$OUT_DIR/app-enc.bin"
else
    echo ">>> 默认模式：只烧 app @ 0x20000（Secure Boot 保护 <0x8000，不碰 bootloader）"
    esptool.py -p "$PORT" -b 460800 --chip esp32c5 \
        write_flash --flash_mode dio --flash_freq 80m --flash_size 4MB \
        $ADDR_APP "$OUT_DIR/app-enc.bin"
fi

echo ""
echo "=== 完成！设备应正常启动 ==="
echo "本次烧录镜像已存于: $OUT_DIR/app-enc.bin"
echo "本次备份: $BK"
echo "查看日志: idf.py --preview -p $PORT monitor"
