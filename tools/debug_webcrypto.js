// 用 Node WebCrypto 完全模拟网页验签流程，拿日志里的真实数据验证
const { webcrypto } = require('crypto');
const crypto = webcrypto;

// 日志里的真实数据
const CERT_B64 = "AFIBBCSH0AZgU4FyUsUL2a/GZTHpC+DKg937pfXy54+tNo1RYWgFitT2r1A3dWlDnqzWLQPh0Qi/lkwwwVdBbJtKFWoAAAAAariJNxi2QOAJy67PAEDt39fueIbFlBoB+3PVLAh3L2B1YiTeUJBPMx+vpaT/6xf7IHaJeg0zGKIo23/3pGoN9atmXCQEVFtAUoMx4XZX";
const AUTH_NONCE_B64 = "GwUR/f7pl9OuIeTAmfPuC3SjzGTeF3V7CLKa5DLcjXg=";
const AUTH_SIG_B64 = "+TtNUgnMAryialuJZbtVKBkwCupkG/e8rGNd2M9JM5SJ4vfdvam5sX608lsVhBUkaTzAsr+ZZJ40Bx7iR0imew==";
const CA_PUBKEY_B64 = "BO+1Mjj2ZeglAd76ArgCaujE0FdBr+TURI6nlaMaAYAN7pZN04F3yhqzxGhDalco5cGMqSdVtgUT9Tu4iFbG9Q0=";

function b64ToBytes(b64) {
  return new Uint8Array(Buffer.from(b64, "base64"));
}
function bytesToB64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

(async () => {
  // --- 证书验签 ---
  const cert = b64ToBytes(CERT_B64);
  const plen = (cert[0] << 8) | cert[1];
  const payload = cert.slice(2, 2 + plen);
  const slen = (cert[2 + plen] << 8) | cert[2 + plen + 1];
  const sig = cert.slice(4 + plen, 4 + plen + slen);
  const devicePub = payload.slice(1, 66);
  console.log("payload len:", plen, "sig len:", slen);
  console.log("devicePub[0]:", devicePub[0].toString(16), "(应为 04)");

  const caPub = await crypto.subtle.importKey(
    "raw", b64ToBytes(CA_PUBKEY_B64).slice(0, 65),
    { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const okCert = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" }, caPub, sig, payload);
  console.log("证书验签:", okCert ? "✅通过" : "❌失败");

  // --- AUTH 挑战响应验签 ---
  const nonce = b64ToBytes(AUTH_NONCE_B64);
  const sigRaw = b64ToBytes(AUTH_SIG_B64);
  console.log("nonce len:", nonce.length, "sig len:", sigRaw.length);

  const devKey = await crypto.subtle.importKey(
    "raw", devicePub, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);

  // 尝试1：raw 签名 + Uint8Array nonce
  const ok1 = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" }, devKey, sigRaw, nonce);
  console.log("AUTH 验签(raw sig + Uint8Array):", ok1 ? "✅通过" : "❌失败");

  // 尝试2：raw 签名 + ArrayBuffer nonce
  const ok2 = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" }, devKey, sigRaw, nonce.buffer);
  console.log("AUTH 验签(raw sig + ArrayBuffer):", ok2 ? "✅通过" : "❌失败");

  // 尝试3：DER 格式签名（把 raw 转 DER）
  function rawToDer(raw) {
    const r = raw.slice(0, 32), s = raw.slice(32, 64);
    function trim(b){ let i=0; while(i<b.length-1 && b[i]===0) i++; let o=b.slice(i); if(o[0]&0x80) o=Buffer.concat([Buffer.from([0]),o]); return o; }
    const rr = trim(Buffer.from(r)), ss = trim(Buffer.from(s));
    const body = Buffer.concat([Buffer.from([0x02, rr.length]), rr, Buffer.from([0x02, ss.length]), ss]);
    return Buffer.concat([Buffer.from([0x30, body.length]), body]);
  }
  const derSig = rawToDer(sigRaw);
  const ok3 = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" }, devKey, derSig, nonce);
  console.log("AUTH 验签(DER sig + Uint8Array):", ok3 ? "✅通过" : "❌失败");
})();
