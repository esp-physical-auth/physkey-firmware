#!/usr/bin/env python3
"""BLE 连通性测试：连 ATRI-TOTP -> AUTHPASS -> WA_REG -> WA_PUB

用于独立验证 PC <-> ESP32 的 WebAuthn 桥（不启动 passless）。
密码用 getpass 交互输入，不落盘。
"""
import asyncio
import base64
import getpass
import sys

from bleak import BleakClient, BleakScanner

DEVICE_NAME = "ATRI-TOTP"
UUID_RX = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"  # 写入
UUID_TX = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"  # 通知

_buf = ""
_lines: list[str] = []
_lines_evt: asyncio.Event = asyncio.Event()


def on_notify(_, data: bytearray):
    global _buf
    _buf += data.decode(errors="replace")
    while "\n" in _buf:
        line, _buf = _buf.split("\n", 1)
        line = line.strip()
        if line:
            print(f"[<<] {line}", flush=True)
            _lines.append(line)
            _lines_evt.set()


async def send(client, cmd: str) -> str:
    """发送命令，收集到第一条 OK/ERR 行（含其之前的数据行），返回全部行。"""
    print(f"[>>] {cmd}", flush=True)
    _lines.clear()
    _lines_evt.clear()
    await client.write_gatt_char(UUID_RX, (cmd + "\n").encode(), response=True)
    deadline = asyncio.get_event_loop().time() + 15
    while True:
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            return "<timeout>"
        try:
            await asyncio.wait_for(_lines_evt.wait(), timeout=remaining)
        except asyncio.TimeoutError:
            return "<timeout>"
        _lines_evt.clear()
        # ESP32 每条命令的响应里只要出现 OK/ERR 行就算本轮结束。
        # 注意：WA_REG 会分两条 Notify 先后到达（'OK CRED:...' 与 'PUBKEY:...'），
        # OK 行可能不是最后一行，因此用 any() 判断而非只看最后一行。
        # 之后再多等一小段，把紧随其后的数据行（如 PUBKEY/LIST 行）收全。
        if _lines and any(l.startswith("OK") or l.startswith("ERR") for l in _lines):
            await asyncio.sleep(0.8)
            return "\n".join(_lines)


async def main():
    print("扫描设备...", flush=True)
    dev = await BleakScanner.find_device_by_name(DEVICE_NAME, timeout=20)
    if dev is None:
        print("❌ 没找到设备！确认板子在广播。", flush=True)
        return 1
    print(f"✅ 找到 {dev.name} ({dev.address})", flush=True)

    async with BleakClient(dev) as client:
        print(f"✅ 已连接: {client.is_connected}", flush=True)
        await client.start_notify(UUID_TX, on_notify)
        print("✅ Notify 已开启\n", flush=True)

        # 1) 查询是否设过密码
        r = await send(client, "HASPASS")
        if "no pass" in r:
            print("设备未设密码，跳过解锁", flush=True)
        else:
            pw = getpass.getpass("请输入 ESP32 密码 (AUTHPASS): ")
            r = await send(client, f"AUTHPASS {pw}")
            if not r.startswith("OK"):
                print(f"❌ 解锁失败: {r}", flush=True)
                return 1
            print("✅ 解锁成功", flush=True)

        # 2) 注册一把测试凭证 -> 两行: "OK CRED:<hex>" + "PUBKEY:<b64>"
        r = await send(client, "WA_REG nettest user1")
        cred_id = None
        for ln in r.splitlines():
            if ln.startswith("OK CRED:"):
                cred_id = ln[len("OK CRED:"):].strip()
            elif ln.startswith("PUBKEY:"):
                print(f"✅ 公钥({len(ln) - 7}b64): {ln[7:][:24]}...", flush=True)
        if not cred_id:
            print(f"❌ WA_REG 失败: {r}", flush=True)
            return 1
        print(f"✅ 凭证 id={cred_id}", flush=True)

        # 3) 取公钥核对 -> "OK PUBKEY:<b64>"
        r = await send(client, f"WA_PUB {cred_id}")
        if "PUBKEY:" in r:
            print(f"✅ WA_PUB 公钥: {r.split('PUBKEY:')[1][:24]}...", flush=True)
        else:
            print(f"⚠️ WA_PUB: {r}", flush=True)

        # 4) 对 32 字节摘要直接签名（模拟 CTAP 的 WA_SIGNHASH 路径）
        digest = bytes(range(32))
        hb64 = base64.b64encode(digest).decode()
        r = await send(client, f"WA_SIGNHASH {cred_id} {hb64}")
        if "OK SIG:" in r:
            sig = base64.b64decode(r.split("OK SIG:")[1].strip())
            print(f"✅ 签名 {len(sig)} 字节: {sig.hex()[:32]}...", flush=True)
        else:
            print(f"❌ 签名失败: {r}", flush=True)

        # 5) 列出
        await send(client, "WA_LIST")

        # 6) 清理测试凭证
        await send(client, f"WA_DEL {cred_id}")

        await asyncio.sleep(1)
        await client.stop_notify(UUID_TX)

    print("\n=== 连通性测试完成 ===", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
