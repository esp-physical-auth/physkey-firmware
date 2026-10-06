#!/usr/bin/env python3
"""
atri-ca.py — ATRI TOTP 信任链 CA 工具（SSL/TLS 式证书链）

信任模型（三级链，标准证书链验证，客户端验证全程离线、不联网）：

    根 CA (root)                    私钥离线保管，绝不进 Worker、绝不联网
      └─签发→ 中间 CA 证书 (0x10)   Worker 用根 CA 私钥签发（一次性签发动作）
                └─签发→ 设备证书 (0x02)  中间 CA 私钥在部署者本地签发
                          └── 设备

    客户端只内置【根 CA 公钥】一行常量，验签链：
      根CA公钥 → 验"中间CA证书" → 取中间CA公钥 → 验"设备证书" → 取设备公钥 → 验 AUTH 挑战响应

设计约束（用户需求）：
  - 代码内【绝不写死域名/IP】：客户端不内置任何 URL。
  - 客户端【绝不联网】：验签仅用本地根 CA 公钥 + 设备返回的证书链，纯离线。

证书格式（自定义简单二进制，非 X.509，网页好解析）：

  中间 CA 证书（由根 CA 签发）：
     uca_payload = 0x10 || id_len(1) || deployment_id || userCA_pub(65) || issue_time(8) || serial(8)
     uca_cert    = len(2) || uca_payload || slen(2) || sig(64)     # 验签者 = 根 CA 公钥

  设备证书（由中间 CA 签发）：
     dev_payload = 0x02 || id_len(1) || deployment_id || device_pub(65) || issue_time(8) || serial(8)
     dev_cert    = len(2) || dev_payload || slen(2) || sig(64)     # 验签者 = 中间 CA 公钥

  设备下发串（GETCERT 返回）：dev_cert_b64 | uca_cert_b64     （两段，用 '|' 拼接）

向后兼容：
  单段模式（仅有 0x02 设备证书，无中间 CA 证书）仍支持：直接用内置根 CA 公钥验（等价旧单 CA）。
  旧 0x01 格式（无 deployment_id）仍可解析。

用法：
  # —— 根 CA（唯一权威，离线）——
  python3 atri-ca.py root-init                                  # 生成根 CA 密钥对
  python3 atri-ca.py root-pub                                   # 打印根 CA 公钥(base64)，嵌客户端
  python3 atri-ca.py root-sign-uca <uca_pub_b64|hex> [deployment_id]
                                                                # 根 CA 给中间 CA 公钥签“中间 CA 证书”
  python3 atri-ca.py root-verify-uca <uca_cert_b64>             # 用根 CA 公钥验中间 CA 证书

  # —— 中间 CA（部署者本机）——
  python3 atri-ca.py uca-init                                   # 生成中间 CA 密钥对
  python3 atri-ca.py uca-pub                                    # 打印中间 CA 公钥
  python3 atri-ca.py uca-sign <device_pub_hex> [deployment_id] [uca_cert_b64]
                                                                # 中间 CA 给设备签证书，并可拼两段链
  python3 atri-ca.py uca-verify <dev_cert_b64> [uca_cert_b64]   # 验设备证书（可选两段链）
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
# 根 CA（离线，唯一权威）
ROOT_PRIV = os.path.join(CA_DIR, "root", "root_private.pem")
ROOT_PUB = os.path.join(CA_DIR, "root", "root_public.pem")
ROOT_META = os.path.join(CA_DIR, "root", "root_meta.json")
# 中间 CA（部署者本机）
UCA_PRIV = os.path.join(CA_DIR, "uca_private.pem")
UCA_PUB = os.path.join(CA_DIR, "uca_public.pem")
UCA_META = os.path.join(CA_DIR, "uca_meta.json")
# 兼容旧命名（旧工具用 ca_private.pem 等）
LEGACY_PRIV = os.path.join(CA_DIR, "ca_private.pem")
LEGACY_PUB = os.path.join(CA_DIR, "ca_public.pem")


# ---- 通用：构建/解析/签名证书 ----

def _raw_sig_from_der(der_sig: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(der_sig)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _der_sig_from_raw(raw_sig: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    r = int.from_bytes(raw_sig[:32], "big")
    s = int.from_bytes(raw_sig[32:], "big")
    return encode_dss_signature(r, s)


def _split_cert(cert: bytes):
    """拆开证书，返回 (payload, raw_sig)。"""
    plen = struct.unpack(">H", cert[:2])[0]
    payload = cert[2:2 + plen]
    off = 2 + plen
    slen = struct.unpack(">H", cert[off:off + 2])[0]
    raw_sig = cert[off + 2:off + 2 + slen]
    return payload, raw_sig


def _build_cert(payload: bytes, priv) -> bytes:
    """用 priv 签名 payload，拼成完整证书。"""
    der_sig = priv.sign(payload, ec.ECDSA(hashes.SHA256()))
    raw_sig = _raw_sig_from_der(der_sig)
    return struct.pack(">H", len(payload)) + payload + struct.pack(">H", len(raw_sig)) + raw_sig


def _pubkey_uncompressed(priv) -> bytes:
    nums = priv.public_key().public_numbers()
    return b"\x04" + nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")


def _pubkey_from_b64_or_hex(s: str) -> bytes:
    s = s.strip()
    try:
        if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) == 130:
            return bytes.fromhex(s)
    except Exception:
        pass
    return base64.b64decode(s)


def ensure_dir():
    os.makedirs(CA_DIR, exist_ok=True)


def ensure_root_dir():
    os.makedirs(os.path.join(CA_DIR, "root"), exist_ok=True)


def _write_keypair(priv_path, pub_path, meta_path):
    """生成 ECDSA P-256 密钥对并存盘，返回公钥 raw(65)。"""
    priv = ec.generate_private_key(ec.SECP256R1())
    with open(priv_path, "wb") as f:
        f.write(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
    with open(pub_path, "wb") as f:
        f.write(priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))
    raw = _pubkey_uncompressed(priv)
    meta = {
        "created": int(time.time()),
        "pubkey_hex": raw.hex(),
        "pubkey_b64": base64.b64encode(raw).decode(),
        "pubkey_fp_sha256": hashlib.sha256(raw).hexdigest(),
    }
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    return raw


# ---- 根 CA ----

def cmd_root_init():
    ensure_root_dir()
    if os.path.exists(ROOT_PRIV):
        print(f"[!] 根 CA 密钥已存在: {ROOT_PRIV}")
        print("    如需重建请先删除。")
        return
    raw = _write_keypair(ROOT_PRIV, ROOT_PUB, ROOT_META)
    print("[✓] 根 CA 密钥对已生成（唯一权威）")
    print(f"    私钥: {ROOT_PRIV}  ← 务必离线保管好")
    print(f"    公钥: {ROOT_PUB}")
    print(f"    根 CA 公钥(base64, 嵌客户端用): {base64.b64encode(raw).decode()}")
    print(f"    根 CA 公钥指纹(SHA256): {hashlib.sha256(raw).hexdigest()}")


def _load_root_priv():
    if not os.path.exists(ROOT_PRIV):
        print("[✗] 未找到根 CA 私钥，请先运行: python3 atri-ca.py root-init")
        sys.exit(1)
    with open(ROOT_PRIV, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def cmd_root_pub():
    if not os.path.exists(ROOT_META):
        print("[✗] 未找到根 CA，请先运行 root-init")
        sys.exit(1)
    with open(ROOT_META) as f:
        print(json.load(f)["pubkey_b64"])


def build_uca_payload(uca_pub: bytes, deployment_id: str = "",
                      issue_time: int = None, serial: int = None) -> bytes:
    """构造中间 CA 证书 payload（格式 0x10）。"""
    if issue_time is None:
        issue_time = int(time.time())
    if serial is None:
        serial = secrets.randbits(63)
    did = (deployment_id or "").encode("utf-8")
    if len(did) > 255:
        raise ValueError("deployment_id 过长（上限 255 字节）")
    return (b"\x10" + bytes([len(did)]) + did + uca_pub +
            struct.pack(">Q", issue_time) + struct.pack(">Q", serial))


def cmd_root_sign_uca(uca_pub_arg: str, deployment_id: str = ""):
    """用根 CA 私钥给中间 CA 公钥签发“中间 CA 证书”。"""
    uca_pub = _pubkey_from_b64_or_hex(uca_pub_arg)
    if len(uca_pub) != 65 or uca_pub[0] != 0x04:
        print(f"[✗] 中间 CA 公钥格式错误，应为 65 字节未压缩点，实际 {len(uca_pub)} 字节")
        sys.exit(1)
    priv = _load_root_priv()
    payload = build_uca_payload(uca_pub, deployment_id)
    cert = _build_cert(payload, priv)
    cert_b64 = base64.b64encode(cert).decode()
    ensure_dir()
    with open(os.path.join(CA_DIR, "uca_cert.b64"), "w") as f:
        f.write(cert_b64)
    print("[✓] 中间 CA 证书已签发（由根 CA）")
    print(f"    中间 CA 公钥: {uca_pub.hex()}")
    print(f"    部署标识: {deployment_id or '(无)'}")
    print(f"    中间 CA 证书(base64):\n    {cert_b64}")


def cmd_root_verify_uca(cert_b64: str):
    """用根 CA 公钥验证中间 CA 证书。"""
    cert = base64.b64decode(cert_b64.strip())
    payload, raw_sig = _split_cert(cert)
    with open(ROOT_PUB, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    try:
        pub.verify(_der_sig_from_raw(raw_sig), payload, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        print("[✗] 验签失败：中间 CA 证书非本根 CA 签发！")
        sys.exit(2)
    ver, deployment_id, uca_pub, _issue_time, _serial = parse_payload(payload)
    print("[✓] 中间 CA 证书验签通过")
    print(f"    部署标识: {deployment_id or '(无)'}")
    print(f"    中间 CA 公钥: {uca_pub.hex()}")


# ---- 中间 CA ----

def cmd_uca_init():
    ensure_dir()
    if os.path.exists(UCA_PRIV):
        print(f"[!] 中间 CA 密钥已存在: {UCA_PRIV}")
        print("    如需重建请先删除。")
        return
    raw = _write_keypair(UCA_PRIV, UCA_PUB, UCA_META)
    print("[✓] 中间 CA 密钥对已生成")
    print(f"    私钥: {UCA_PRIV}")
    print(f"    公钥: {UCA_PUB}")
    print(f"    中间 CA 公钥(base64, 交给 Worker/根CA 签“中间 CA 证书”): {base64.b64encode(raw).decode()}")
    print(f"    公钥指纹(SHA256): {hashlib.sha256(raw).hexdigest()}")
    print()
    print("下一步：把上面的公钥提交给证书签发器（Worker /sign-uca，或本地 root-sign-uca）换取中间 CA 证书。")


def load_uca_priv():
    if not os.path.exists(UCA_PRIV):
        print("[✗] 未找到中间 CA 私钥，请先运行: python3 atri-ca.py uca-init")
        sys.exit(1)
    with open(UCA_PRIV, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def build_payload(device_pubkey: bytes, deployment_id: str = "", issue_time: int = None, serial: int = None) -> bytes:
    """构造设备证书 payload（格式 0x02，含部署标识）。"""
    if issue_time is None:
        issue_time = int(time.time())
    if serial is None:
        serial = secrets.randbits(63)
    did = (deployment_id or "").encode("utf-8")
    if len(did) > 255:
        raise ValueError("deployment_id 过长（上限 255 字节）")
    return (b"\x02" + bytes([len(did)]) + did + device_pubkey +
            struct.pack(">Q", issue_time) + struct.pack(">Q", serial))


def cmd_uca_sign(device_pubkey_hex: str, deployment_id: str = "", uca_cert_b64: str = ""):
    device_pubkey = bytes.fromhex(device_pubkey_hex.strip())
    if len(device_pubkey) != 65 or device_pubkey[0] != 0x04:
        print(f"[✗] 设备公钥格式错误，应为 65 字节未压缩点(0x04开头)，实际 {len(device_pubkey)} 字节")
        sys.exit(1)

    priv = load_uca_priv()
    payload = build_payload(device_pubkey, deployment_id)
    cert = _build_cert(payload, priv)
    cert_b64 = base64.b64encode(cert).decode()

    ensure_dir()
    with open(os.path.join(CA_DIR, "device_cert.der"), "wb") as f:
        f.write(cert)
    with open(os.path.join(CA_DIR, "device_cert.b64"), "w") as f:
        f.write(cert_b64)

    print("[✓] 设备证书已签发（由中间 CA）")
    print(f"    设备公钥: {device_pubkey.hex()}")
    print(f"    部署标识: {deployment_id or '(无)'}")
    print(f"    证书长度: {len(cert)} 字节")
    print(f"    设备证书(base64):\n    {cert_b64}")

    if uca_cert_b64:
        uca = uca_cert_b64.strip()
        combined = cert_b64 + "|" + uca
        with open(os.path.join(CA_DIR, "device_chain.b64"), "w") as f:
            f.write(combined)
        print()
        print("[✓] 证书链已拼好（设备证书|中间CA证书），烧写用：")
        print(f"    SETCERT {combined}")
        print()
        print("提示：SETCERT 需同时写入两段（固件分段存储，GETCERT 一并返回）。")


def cmd_uca_pub():
    if not os.path.exists(UCA_META):
        print("[✗] 未找到中间 CA，请先运行 uca-init")
        sys.exit(1)
    with open(UCA_META) as f:
        print(json.load(f)["pubkey_b64"])


def parse_payload(payload: bytes):
    """解析 payload，返回 (version, deployment_id, subject_pub, issue_time, serial)。
    兼容：0x01（旧，无标识）、0x02（设备证书）、0x10（中间 CA 证书）。"""
    ver = payload[0]
    if ver in (0x02, 0x10):
        id_len = payload[1]
        deployment_id = payload[2:2 + id_len].decode("utf-8", errors="replace")
        off = 2 + id_len
    elif ver == 0x01:
        deployment_id = ""
        off = 1
    else:
        raise ValueError(f"未知 payload 版本: 0x{ver:02x}")
    subject_pub = payload[off:off + 65]
    issue_time = struct.unpack(">Q", payload[off + 65:off + 73])[0]
    serial = struct.unpack(">Q", payload[off + 73:off + 81])[0]
    return ver, deployment_id, subject_pub, issue_time, serial


def cmd_uca_verify(cert_b64: str, uca_cert_b64: str = ""):
    cert = base64.b64decode(cert_b64.strip())
    payload, raw_sig = _split_cert(cert)

    if uca_cert_b64:
        # 三段链：根CA公钥验中间CA证书 → 取中间CA公钥 → 验设备证书
        uca = base64.b64decode(uca_cert_b64.strip())
        uca_payload, uca_sig = _split_cert(uca)
        with open(ROOT_PUB, "rb") as f:
            root_pub = serialization.load_pem_public_key(f.read())
        try:
            root_pub.verify(_der_sig_from_raw(uca_sig), uca_payload, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            print("[✗] 中间 CA 证书验签失败：非本根 CA 签发！")
            sys.exit(2)
        _, _, uca_pub, _, _ = parse_payload(uca_payload)
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), uca_pub)
        print("[✓] 中间 CA 证书验签通过（根 CA 可信）")
    else:
        # 单段模式：用中间 CA 公钥（或旧 ca_public.pem）验
        pub_path = UCA_PUB if os.path.exists(UCA_PUB) else LEGACY_PUB
        with open(pub_path, "rb") as f:
            pub = serialization.load_pem_public_key(f.read())

    try:
        pub.verify(_der_sig_from_raw(raw_sig), payload, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        print("[✗] 设备证书验签失败！")
        sys.exit(2)

    ver, deployment_id, device_pub, issue_time, serial = parse_payload(payload)
    print("[✓] 设备证书验签通过：设备可信")
    print(f"    格式版本: 0x{ver:02x}")
    print(f"    部署标识: {deployment_id or '(无)'}")
    print(f"    设备公钥: {device_pub.hex()}")
    print(f"    签发时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(issue_time))}")
    print(f"    序列号  : {serial}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)
    cmd = sys.argv[1]
    # —— 根 CA ——
    if cmd == "root-init":
        cmd_root_init()
    elif cmd == "root-pub":
        cmd_root_pub()
    elif cmd == "root-sign-uca":
        if len(sys.argv) < 3:
            print("用法: python3 atri-ca.py root-sign-uca <uca_pub_b64|hex> [deployment_id]")
            sys.exit(1)
        cmd_root_sign_uca(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "")
    elif cmd == "root-verify-uca":
        if len(sys.argv) < 3:
            print("用法: python3 atri-ca.py root-verify-uca <uca_cert_b64>")
            sys.exit(1)
        cmd_root_verify_uca(sys.argv[2])
    # —— 中间 CA ——
    elif cmd == "uca-init":
        cmd_uca_init()
    elif cmd == "uca-pub":
        cmd_uca_pub()
    elif cmd == "uca-sign":
        if len(sys.argv) < 3:
            print("用法: python3 atri-ca.py uca-sign <device_pubkey_hex> [deployment_id] [uca_cert_b64]")
            sys.exit(1)
        cmd_uca_sign(
            sys.argv[2],
            sys.argv[3] if len(sys.argv) > 3 else "",
            sys.argv[4] if len(sys.argv) > 4 else "",
        )
    elif cmd == "uca-verify":
        if len(sys.argv) < 3:
            print("用法: python3 atri-ca.py uca-verify <dev_cert_b64> [uca_cert_b64]")
            sys.exit(1)
        cmd_uca_verify(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "")
    # —— 兼容别名 ——
    elif cmd in ("init", "capub", "sign", "verify"):
        print(f"[i] 旧命令 '{cmd}' 已更名，请用："
              f"init→uca-init, capub→uca-pub, sign→uca-sign, verify→uca-verify")
        sys.exit(1)
    else:
        print(f"未知命令: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
