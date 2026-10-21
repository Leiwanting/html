/* ============================================================
 * 加密模式扩展：A 组 Encrypt-then-MAC（RFC 7366）+ E 组 biIGE
 * ============================================================
 * A 组 EtM：给任意「无认证」模式附加 MAC，解决 13 个裸奔模式
 *           （CBC/CFB/OFB/CTR/ECB/PCBC/LRW/CTS×3/CFB8/CFB1/XTS/IGE/biIGE）
 *           改一个字节不报错的问题。
 * E 组 biIGE：OpenSSL AES_bi_ige_encrypt 语义，IGE 串行两次，双向错误传播。
 *
 * 参照物：work/b78/ref_biige_etm.py（Python，cryptography 单块 AES + hashlib/hmac 独立实现）
 * ============================================================ */

/* ---------- E 组：biIGE（双向 IGE，OpenSSL AES_bi_ige_encrypt） ----------
 * 加密：C = IGE_ivec1( IGE_ivec2(P) )      —— 第一次带填充，第二次输入已块对齐不再填充
 * 解密：P = IGE_ivec2⁻¹( IGE_ivec1⁻¹(C) )  —— 第二次才去填充
 * IV 共 4×块长：前 2×bs 是 ivec1，后 2×bs 是 ivec2。
 * 注意顺序：OpenSSL 加密时先传 ivec2 后传 ivec1，解密时先 ivec1 后 ivec2。
 */
function biigeEnc(plain, bs, blockFn, padMode, iv) {
  if (iv.length !== bs * 4) throw new Error('biIGE 的 IV 必须为 ' + (bs * 4) + ' 字节（' + (bs * 8) + ' 位 Hex）：前 ' + (bs * 2) + ' 字节是 ivec1，后 ' + (bs * 2) + ' 字节是 ivec2');
  var ivec1 = iv.subarray(0, bs * 2), ivec2 = iv.subarray(bs * 2, bs * 4);
  var t = igeEnc(plain, bs, blockFn, padMode, ivec2);        /* 第一次：带填充 */
  return igeEncRaw(t, bs, blockFn, ivec1);                   /* 第二次：已对齐，不填充 */
}
function biigeDec(cipher, bs, invFn, padMode, iv) {
  if (iv.length !== bs * 4) throw new Error('biIGE 的 IV 必须为 ' + (bs * 4) + ' 字节');
  var ivec1 = iv.subarray(0, bs * 2), ivec2 = iv.subarray(bs * 2, bs * 4);
  var t = igeDecRaw(cipher, bs, invFn, ivec1);               /* 第一次：不去填充 */
  return igeDec(t, bs, invFn, padMode, ivec2);               /* 第二次：去填充 */
}
/* 无填充版 IGE：输入必须已是块长整数倍 */
function igeEncRaw(d, bs, blockFn, iv) {
  if (d.length === 0 || d.length % bs !== 0) throw new Error('biIGE 内部：中间结果长度必须是块大小整数倍');
  var out = new Uint8Array(d.length);
  var cp = new Uint8Array(iv.subarray(0, bs)), xp = new Uint8Array(iv.subarray(bs, bs * 2));
  var P = new Uint8Array(bs), C = new Uint8Array(bs), i, j, x = new Uint8Array(bs);
  for (i = 0; i < d.length; i += bs) {
    for (j = 0; j < bs; j++) x[j] = d[i + j] ^ cp[j];
    var y = blockFn(x);
    for (j = 0; j < bs; j++) C[j] = y[j] ^ xp[j];
    out.set(C, i);
    P.set(d.subarray(i, i + bs)); cp.set(C); xp.set(P);
  }
  return out;
}
function igeDecRaw(cipher, bs, invFn, iv) {
  if (cipher.length === 0 || cipher.length % bs !== 0) throw new Error('biIGE 密文长度必须是块大小 ' + bs + ' 的整数倍');
  var out = new Uint8Array(cipher.length);
  var cp = new Uint8Array(iv.subarray(0, bs)), xp = new Uint8Array(iv.subarray(bs, bs * 2));
  var P = new Uint8Array(bs), C = new Uint8Array(bs), i, j, x = new Uint8Array(bs);
  for (i = 0; i < cipher.length; i += bs) {
    C.set(cipher.subarray(i, i + bs));
    for (j = 0; j < bs; j++) x[j] = C[j] ^ xp[j];
    var y = invFn(x);
    for (j = 0; j < bs; j++) P[j] = y[j] ^ cp[j];
    out.set(P, i);
    xp.set(P); cp.set(C);
  }
  return out;
}

/* ---------- A 组：Encrypt-then-MAC（RFC 7366） ---------- */
var ETM_LIST = [
  { id: 'none',         name: '无（不附加认证）', tagLen: 0 },
  { id: 'hmac-sha256',  name: 'EtM · HMAC-SHA-256',  tagLen: 32 },
  { id: 'hmac-sha512',  name: 'EtM · HMAC-SHA-512',  tagLen: 64 },
  { id: 'hmac-sha3-256',name: 'EtM · HMAC-SHA3-256', tagLen: 32 },
  { id: 'cmac-aes',     name: 'EtM · AES-CMAC',      tagLen: 16 },
  { id: 'poly1305',     name: 'EtM · Poly1305',      tagLen: 16 }
];
function etmTagLen(id) {
  for (var i = 0; i < ETM_LIST.length; i++) if (ETM_LIST[i].id === id) return ETM_LIST[i].tagLen;
  return 0;
}
/* MAC 密钥派生：SHA256(key ‖ 'etm-mac' ‖ macName ‖ BE32(ctr)) 循环扩展。
   独立于分组算法，所以 13 个模式都能用同一套。 */
function etmDeriveKey(keyBytes, macName, need) {
  var seed = concatBytes(keyBytes, strToBytes('etm-mac'), strToBytes(macName));
  var out = new Uint8Array(0);
  for (var ctr = 0; out.length < need; ctr++) {
    var block = sha256Bytes(concatBytes(seed, new Uint8Array([(ctr >>> 24) & 255, (ctr >>> 16) & 255, (ctr >>> 8) & 255, ctr & 255])));
    out = concatBytes(out, block);
  }
  return out.subarray(0, need);
}
/* MAC 输入 = lp(IV) ‖ lp(AAD) ‖ lp(CT)，lp 是 4 字节大端长度前缀。
   带长度前缀是为了消除各段边界歧义（否则 IV/AAD/CT 长度可变时可延展）。 */
function etmMacInput(iv, aad, ct) {
  function lp(x) {
    var n = x ? x.length : 0;
    return concatBytes(new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]), x || new Uint8Array(0));
  }
  return concatBytes(lp(iv), lp(aad), lp(ct));
}
/* HMAC-SHA3-256。⚠ SHA3-256 的 HMAC 块大小是 136 字节（rate = 200-2*32），
   不是 SHA-256 的 64 —— 写错会得到完全不同且不报错的 tag。 */
function hmacSha3_256(keyBytes, msg) {
  var BLK = 136;
  var k = keyBytes;
  if (k.length > BLK) k = sha3Digest(k, 32);
  var ik = new Uint8Array(BLK), ok = new Uint8Array(BLK);
  for (var i = 0; i < BLK; i++) { var kb = i < k.length ? k[i] : 0; ik[i] = kb ^ 0x36; ok[i] = kb ^ 0x5c; }
  return sha3Digest(concatBytes(ok, sha3Digest(concatBytes(ik, msg), 32)), 32);
}
/* 计算 EtM 标签。iv 可为 null（ECB/XTS 等无 IV 模式）。 */
function etmTag(macName, keyBytes, iv, aad, ct) {
  var msg = etmMacInput(iv, aad, ct);
  if (macName === 'hmac-sha256') return hmacSha256(etmDeriveKey(keyBytes, macName, 32), msg);
  if (macName === 'hmac-sha512') return hmacSha512(etmDeriveKey(keyBytes, macName, 64), msg);
  if (macName === 'hmac-sha3-256') return hmacSha3_256(etmDeriveKey(keyBytes, macName, 32), msg);
  if (macName === 'cmac-aes') return cmacAes(etmDeriveKey(keyBytes, macName, 16), msg);
  if (macName === 'poly1305') return poly1305Mac(msg, etmDeriveKey(keyBytes, macName, 32));
  throw new Error('未知的 EtM 算法: ' + macName);
}
/* 常量时间比较（不用 === 短路，避免通过耗时泄漏标签比对位置） */
function etmCtEq(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  var d = 0;
  for (var i = 0; i < a.length; i++) d |= (a[i] ^ b[i]);
  return d === 0;
}
/* 加密侧：把 tag 追加到密文尾部 */
function etmAppend(macName, keyBytes, iv, aad, ct) {
  if (!macName || macName === 'none') return ct;
  return concatBytes(ct, etmTag(macName, keyBytes, iv, aad, ct));
}
/* 解密侧：分离尾部 tag 并校验；失败抛错（绝不返回未校验的数据） */
function etmSplit(macName, keyBytes, iv, aad, bufWithTag) {
  var tl = etmTagLen(macName);
  if (!tl) return bufWithTag;
  if (bufWithTag.length < tl) throw new Error('EtM 数据长度不足（至少需要 ' + tl + ' 字节的认证标签），请确认「附加认证」选择一致');
  var ct = bufWithTag.subarray(0, bufWithTag.length - tl);
  var tag = bufWithTag.subarray(bufWithTag.length - tl);
  if (!etmCtEq(tag, etmTag(macName, keyBytes, iv, aad, ct)))
    throw new Error('认证失败（EtM 标签不匹配）：密文、IV、AAD 或密钥被篡改，或「附加认证」选择不一致');
  return ct;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { biigeEnc: biigeEnc, biigeDec: biigeDec, etmTag: etmTag, etmAppend: etmAppend, etmSplit: etmSplit, ETM_LIST: ETM_LIST };
}
