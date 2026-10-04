import asyncio, base64, os, json, sys
from bleak import BleakClient, BleakScanner
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

RX = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
TX = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"
buf = ""

def n(_, d):
    global buf
    buf += d.decode(errors="replace")

async def main():
    global buf
    dev = await BleakScanner.find_device_by_name("ATRI-TOTP", timeout=20)
    if not dev:
        print("no dev"); return
    async with BleakClient(dev) as c:
        await c.start_notify(TX, n)
        # 取公钥
        buf = ""
        await c.write_gatt_char(RX, b"WHOAMI", response=True)
        await asyncio.sleep(1.5)
        pub_hex = base64.b64decode(buf.split("PUBKEY:")[1].split("\n")[0]).hex()
        # 挑战
        nonce = os.urandom(32)
        buf = ""
        await c.write_gatt_char(RX, ("AUTH " + base64.b64encode(nonce).decode()).encode(), response=True)
        await asyncio.sleep(1.5)
        sig_b64 = buf.split("SIG:")[1].split("\n")[0]
        sig = base64.b64decode(sig_b64)
        # 保存给 Node 复现用
        data = {
            "devicePub": pub_hex,
            "nonceB64": base64.b64encode(nonce).decode(),
            "sigB64": sig_b64,
            "sigHex": sig.hex(),
        }
        with open("/tmp/authdata.json", "w") as f:
            json.dump(data, f)
        print("saved /tmp/authdata.json")
        print("nonce:", data["nonceB64"])
        print("sig:", sig_b64)
        # 电脑验签
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(pub_hex))
        r = int.from_bytes(sig[:32], "big"); s = int.from_bytes(sig[32:], "big")
        try:
            pub.verify(encode_dss_signature(r, s), nonce, ec.ECDSA(hashes.SHA256()))
            print("电脑验签: 通过 ✅")
        except InvalidSignature:
            print("电脑验签: 失败 ❌")

asyncio.run(main())
