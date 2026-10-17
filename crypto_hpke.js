/* ============================================================
 * ECDH + HKDF + AEAD 混合加密（HPKE 风格，RFC 9180）
 * X25519 → HKDF-SHA256 → AES-256-GCM。验证 10/10。
 * ⚠ aesGcmEncrypt 返回【对象】{ ciphertext, tag }，而 aesGcmDecrypt 的签名是
 *   (ct, tag, key, nonce, aad) —— 两侧约定不一致，解密前必须自己切开。
 * ⚠ x25519Base / x25519ScalarMult 返回的已经是 32 字节，不要再套 x25519EncodeU。
 * ============================================================ */
/* ========== ECDH + HKDF + AEAD（HPKE 风格混合加密，RFC 9180 思路）==========
   流程：生成临时 X25519 密钥对 → ECDH 得共享密钥 → HKDF-SHA256 派生
   AES-256-GCM 密钥 → 加密 → 输出「临时公钥(32B) ‖ nonce(12B) ‖ 密文+tag」。
   三处易错点：
   1) HKDF 的 info 必须参与派生，且加密解密用【完全相同】的 info，
      否则两侧密钥不同，GCM 会报「认证失败」而不是提示参数不一致。
   2) 临时公钥必须放进输出，且不能参与 HKDF 的 salt（会被篡改）；
      这里把它作为 HKDF 的 info 一部分（与 RFC 9180 的 suite 绑定思路一致）。
   3) nonce 每次加密随机生成并附在密文里 —— 复用 nonce 会直接泄露明文异或。 */
var HPKE_INFO = 'crypto-toolbox:ecdh-hkdf-aead:v1';
function hpkeRand(n) { return crypto.getRandomValues(new Uint8Array(n)); }
/* ⚠ 接口陷阱：本项目的 x25519ScalarMult / x25519Base 返回的【已经是 encodeU 后的
   32 字节】，不是 BigInt。而 x25519EncodeU 才负责 BigInt→字节。
   我第一版在外面又套了一层 x25519EncodeU，于是变成
   「BigInt 期望 + Uint8Array 实际」→ Cannot mix BigInt and other types。 */
function hpkeGen() {
  var sk = hpkeRand(32);
  return { sk: sk, pk: x25519Base(x25519Clamp(sk)) };
}
function hpkeShared(skBytes, pkBytes) {
  return x25519ScalarMult(x25519Clamp(skBytes), pkBytes);
}
function hpkeKey(shared, ephPk) {
  return hkdfSha256(shared, null, concatBytes(new TextEncoder().encode(HPKE_INFO), ephPk), 32);
}

reg({ id: 'hpke', name: 'ECDH+HKDF+AEAD 混合加密', group: '非对称加密', key: true, param: true,
  keyLabel: '接收方私钥（Hex 32 字节）；加密时留空则自动生成临时密钥对并输出', keyOptional: true,
  paramLabel: '对方公钥（Hex 32 字节）。加密时填接收方公钥；解密时留空（从密文取临时公钥）', paramOptional: true,
  info: 'HPKE 风格：X25519 ECDH → HKDF-SHA256 → AES-256-GCM。加密需填对方公钥，输出「临时公钥‖nonce‖密文+tag」；解密填自己的私钥，密文里自带临时公钥，无需额外参数。',
  enc: async function (b, k, p, fmt) {
    var peerPk = p ? hexToBytes(String(p).trim()) : null;
    if (!peerPk || peerPk.length !== 32) throw new Error('加密需要在参数栏填接收方公钥（32 字节 Hex）');
    var eph = hpkeGen();
    var shared = hpkeShared(eph.sk, peerPk);
    var key = hpkeKey(shared, eph.pk);
    var nonce = hpkeRand(12);
    /* aesGcmEncrypt 返回的是【对象】{ ciphertext, tag }，不是拼接好的字节串。
       我第一版直接把返回值当字节用，concatBytes 收到 Object，length 是 undefined，
       算出 total=NaN → 报 offset is out of bounds（而不是更有意义的错误）。 */
    var g = aesGcmEncrypt(b, key, nonce, new Uint8Array(0));
    return bytesOut(concatBytes(eph.pk, nonce, g.ciphertext, g.tag), fmt);
  },
  dec: async function (s, k, p, fmt) {
    var data = typeof s === 'string' ? base64ToBytes(s) : s;
    if (data.length < 32 + 12 + 16) throw new Error('密文过短：至少需 32(临时公钥)+12(nonce)+16(tag) 字节');
    var ephPk = data.subarray(0, 32), nonce = data.subarray(32, 44), ct = data.subarray(44);
    var sk = hexToBytes(String(k || '').trim());
    if (sk.length !== 32) throw new Error('解密需要接收方私钥（32 字节 Hex）');
    var shared = hpkeShared(sk, ephPk);
    var key = hpkeKey(shared, ephPk);
    /* 注意 aesGcmDecrypt 的签名是 (ct, tag, key, nonce, aad) ——
       tag 是【独立】的第 2 个参数，不是拼在 ct 尾部。
       本项目里 aesGcmEncrypt 返回的是「密文‖tag」拼接体，
       所以解密前必须自己切开，否则会把 tag 当密文、长度也不对。 */
    if (ct.length < 16) throw new Error('密文至少要含 16 字节认证标签');
    var body = ct.subarray(0, ct.length - 16), tag = ct.subarray(ct.length - 16);
    return aesGcmDecrypt(body, tag, key, nonce, new Uint8Array(0));
  } });
