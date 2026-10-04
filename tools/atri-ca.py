#!/usr/bin/env python3
"""
atri-ca.py — 电脑端 CA 工具（ATRI TOTP 信任链）

角色：电脑 = CA，负责：
  1. 生成 CA 密钥对（ECDSA P-256），保存到 ca_private.pem / ca_public.pem
  2. 给 ESP32 设备公钥签发证书 -> device_cert.der（含设备公钥 + 签名）
  3. 导出 CA 公钥为 base64，供嵌进网页

证书格式（自定义简单 DER，非 X.509，够用且网页好解析）：
  payload = 0x01 || device_pubkey(65B) || issue_time(8B unix) || serial(8B)
  cert    = len(payload)(2B BE) || payload || sig_len(2B BE) || signature(64B r||s)

网页端用 CA 公钥（P-256）验签 payload 即可确认设备可信。

用法：
  python3 atri-ca.py init                      # 生成 CA 密钥对
  python3 atri-ca.py sign <device_pubkey_hex>  # 给设备公钥签证书
  python3 atri-ca.py capub                     # 打印 CA 公钥(base64)，嵌入网页用
  python3 atri-ca.py verify <cert_b64>         # 用 CA 公钥验签设备证书
"""

import os
import sys
import json
import struct
import time
import base64
import hashlib
import secrets

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

CA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ca")
CA_PRIV = os.path.join(CA_DIR, "ca_private.pem")
CA_PUB = os.path.join(CA_DIR, "ca_public.pem")
CA_META = os.path.join(CA_DIR, "ca_meta.json")


def ensure_dir():
    os.makedirs(CA_DIR, exist_ok=True)


def cmd_init():
    ensure_dir()
    if os.path.exists(CA_PRIV):
        print(f"[!] CA 密钥已存在: {CA_PRIV}")
        print("    如需重建请先删除。")
        return
    priv = ec.generate_private_key(ec.SECP256R1())
    with open(CA_PRIV, "wb") as f:
        f.write(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
    with open(CA_PUB, "wb") as f:
        f.write(priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))
    # 导出未压缩点 (65 字节)，网页 WebCrypto 用
    nums = priv.public_key().public_numbers()
    raw = b"\x04" + nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    meta = {
        "created": int(time.time()),
        "pubkey_hex": raw.hex(),
        "pubkey_b64": base64.b64encode(raw).decode(),
    }
    with open(CA_META, "w") as f:
        json.dump(meta, f, indent=2)
    print("[✓] CA 密钥对已生成")
    print(f"    私钥: {CA_PRIV}")
    print(f"    公钥: {CA_PUB}")
    print(f"    CA 公钥(base64, 嵌网页用): {meta['pubkey_b64']}")
    print(f"    CA 公钥指纹(SHA256): {hashlib.sha256(raw).hexdigest()}")


def load_ca_priv():
    if not os.path.exists(CA_PRIV):
        print("[✗] 未找到 CA 私钥，请先运行: python3 atri-ca.py init")
        sys.exit(1)
    with open(CA_PRIV, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def build_payload(device_pubkey: bytes, issue_time: int = None, serial: int = None) -> bytes:
    """构造待签名 payload"""
    if issue_time is None:
        issue_time = int(time.time())
    if serial is None:
        serial = secrets.randbits(63)
    payload = b"\x01" + device_pubkey + struct.pack(">Q", issue_time) + struct.pack(">Q", serial)
    return payload


def cmd_sign(device_pubkey_hex: str):
    device_pubkey = bytes.fromhex(device_pubkey_hex.strip())
    if len(device_pubkey) != 65 or device_pubkey[0] != 0x04:
        print(f"[✗] 设备公钥格式错误，应为 65 字节未压缩点(0x04开头)，实际 {len(device_pubkey)} 字节")
        sys.exit(1)

    priv = load_ca_priv()
    payload = build_payload(device_pubkey)
    sig = priv.sign(payload, ec.ECDSA(hashes.SHA256()))
    # DER -> raw (r||s) 64 字节
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")

    cert = (struct.pack(">H", len(payload)) + payload +
            struct.pack(">H", len(raw_sig)) + raw_sig)
    cert_b64 = base64.b64encode(cert).decode()

    # 保存以便查验
    ensure_dir()
    with open(os.path.join(CA_DIR, "device_cert.der"), "wb") as f:
        f.write(cert)
    with open(os.path.join(CA_DIR, "device_cert.b64"), "w") as f:
        f.write(cert_b64)

    print("[✓] 设备证书已签发")
    print(f"    设备公钥: {device_pubkey.hex()}")
    print(f"    证书长度: {len(cert)} 字节")
    print(f"    证书(base64, 用 SETCERT 写回设备):")
    print(f"    {cert_b64}")


def cmd_capub():
    if not os.path.exists(CA_META):
        print("[✗] 未找到 CA，请先运行 init")
        sys.exit(1)
    with open(CA_META) as f:
        meta = json.load(f)
    print(meta["pubkey_b64"])


def cmd_verify(cert_b64: str):
    cert = base64.b64decode(cert_b64.strip())
    plen = struct.unpack(">H", cert[:2])[0]
    payload = cert[2:2 + plen]
    off = 2 + plen
    slen = struct.unpack(">H", cert[off:off + 2])[0]
    raw_sig = cert[off + 2:off + 2 + slen]

    with open(CA_PUB, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())

    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    r = int.from_bytes(raw_sig[:32], "big")
    s = int.from_bytes(raw_sig[32:], "big")
    der_sig = encode_dss_signature(r, s)
    try:
        pub.verify(der_sig, payload, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        print("[✗] 验签失败：证书非本 CA 签发！")
        sys.exit(2)

    device_pub = payload[1:66]
    issue_time = struct.unpack(">Q", payload[66:74])[0]
    serial = struct.unpack(">Q", payload[74:82])[0]
    print("[✓] 验签通过：设备可信")
    print(f"    设备公钥: {device_pub.hex()}")
    print(f"    签发时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(issue_time))}")
    print(f"    序列号  : {serial}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)
    cmd = sys.argv[1]
    if cmd == "init":
        cmd_init()
    elif cmd == "sign":
        if len(sys.argv) < 3:
            print("用法: python3 atri-ca.py sign <device_pubkey_hex>")
            sys.exit(1)
        cmd_sign(sys.argv[2])
    elif cmd == "capub":
        cmd_capub()
    elif cmd == "verify":
        if len(sys.argv) < 3:
            print("用法: python3 atri-ca.py verify <cert_b64>")
            sys.exit(1)
        cmd_verify(sys.argv[2])
    else:
        print(f"未知命令: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
