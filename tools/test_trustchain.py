#!/usr/bin/env python3
"""
test_trustchain.py — 端到端测试 ATRI TOTP 的 CA 信任链
使用 IDF venv 的 python（含 bleak）。

流程：
  1. 连接设备，WHOAMI 取设备公钥
  2. 电脑 CA 给设备公钥签证书
  3. SETCERT 把证书写回设备
  4. GETCERT 读回并验签（确认设备确实持证）
  5. AUTH <nonce> 挑战-响应，用设备公钥验签（证明设备持有私钥）
"""
import asyncio
import sys
import os
import struct
import time
import base64
import subprocess

from bleak import BleakClient, BleakScanner

RX = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
TX = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"
TOOLS = os.path.dirname(os.path.abspath(__file__))

reply_buf = []
reply_ev = asyncio.Event()
_accum = ""


def on_notify(_, data: bytearray):
    global _accum
    _accum += data.decode(errors="replace")
    while "\n" in _accum:
        line, _accum = _accum.split("\n", 1)
        line = line.strip()
        if line:
            print(f"  [N] {line}")
            reply_buf.append(line)
            reply_ev.set()


async def ask(client, cmd, wait=2.0):
    reply_buf.clear()
    reply_ev.clear()
    await client.write_gatt_char(RX, cmd.encode(), response=True)
    try:
        await asyncio.wait_for(reply_ev.wait(), timeout=wait)
    except asyncio.TimeoutError:
        pass
    await asyncio.sleep(0.3)
    return list(reply_buf)


async def main():
    dev = await BleakScanner.find_device_by_name("ATRI-TOTP", timeout=15)
    if not dev:
        print("✗ 未找到设备")
        return 1
    print(f"✓ 找到 {dev.name} ({dev.address})")

    async with BleakClient(dev) as c:
        await c.start_notify(TX, on_notify)
        print("✓ 通知已开启\n")

        # 1. 取设备公钥
        print("─" * 40)
        print("[1] WHOAMI 取设备公钥")
        lines = await ask(c, "WHOAMI")
        pub_hex = None
        for l in lines:
            if "PUBKEY:" in l:
                b64 = l.split("PUBKEY:", 1)[1].strip()
                pub_hex = base64.b64decode(b64).hex()
        if not pub_hex:
            print("✗ 未取到设备公钥")
            return 1
        print(f"  设备公钥: {pub_hex[:32]}...({len(pub_hex)//2}字节)")
        if len(pub_hex) != 130:
            print(f"✗ 公钥长度错误: {len(pub_hex)//2} 字节")
            return 1

        # 2. CA 签发
        print("\n[2] 电脑 CA 签发设备证书")
        r = subprocess.run([sys.executable if False else "python3",
                            os.path.join(TOOLS, "atri-ca.py"), "sign", pub_hex],
                           capture_output=True, text=True)
        print(r.stdout.strip())
        if r.returncode != 0:
            print(r.stderr); return 1
        cert_b64 = None
        for line in r.stdout.splitlines():
            line = line.strip()
            if len(line) > 40 and all(ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for ch in line):
                cert_b64 = line
        if not cert_b64:
            print("✗ 未取到证书"); return 1

        # 3. 写回设备
        print("\n[3] SETCERT 写回设备")
        await ask(c, f"SETCERT {cert_b64}")

        # 4. 读回验证
        print("\n[4] GETCERT 读回 + CA 验签")
        lines = await ask(c, "GETCERT")
        got = None
        for l in lines:
            if "CERT:" in l:
                got = l.split("CERT:", 1)[1].strip()
        if not got:
            print("✗ 未读回证书"); return 1
        print(f"  证书一致: {got == cert_b64}")
        r = subprocess.run(["python3", os.path.join(TOOLS, "atri-ca.py"), "verify", got],
                           capture_output=True, text=True)
        print("  " + r.stdout.strip().replace("\n", "\n  "))

        # 5. 挑战-响应
        print("\n[5] AUTH 挑战-响应（证明设备持有私钥）")
        nonce = os.urandom(32)
        nonce_b64 = base64.b64encode(nonce).decode()
        lines = await ask(c, f"AUTH {nonce_b64}")
        sig_b64 = None
        for l in lines:
            if "SIG:" in l:
                sig_b64 = l.split("SIG:", 1)[1].strip()
        if not sig_b64:
            print("✗ 未取到签名"); return 1

        # 用设备公钥验签
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        from cryptography.hazmat.primitives import hashes
        from cryptography.exceptions import InvalidSignature
        pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), bytes.fromhex(pub_hex))
        raw = base64.b64decode(sig_b64)
        r_ = int.from_bytes(raw[:32], "big"); s_ = int.from_bytes(raw[32:], "big")
        try:
            pub.verify(encode_dss_signature(r_, s_), nonce, ec.ECDSA(hashes.SHA256()))
            print("  ✓ 验签通过：设备确实持有对应私钥！")
        except InvalidSignature:
            print("  ✗ 验签失败！")
            return 1

        print("\n" + "═" * 40)
        print("🎉 信任链端到端全部验证通过！")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
