/* ============================================================
 * AES-XTS（IEEE 1619-2007），磁盘加密事实标准（BitLocker / FileVault / LUKS 均用）
 * 结构：C_j = Enc(K1, P_j ⊕ T_j) ⊕ T_j
 *       T_0 = Enc(K2, 扇区号小端16字节)，T_{j+1} = T_j ⊗ α
 * ⚠ 三个最容易错的点：
 *   1. tweak 初值是【扇区号的小端 16 字节】经 K2 加密，不是明文序号
 *   2. 块内递进是 GF(2^128) 乘 x（左移 1 位，进位时异或 0x87），不是加 1
 *   3. 最后一块不足 16 字节时做 ciphertext stealing：倒数第二块保留尾部，
 *      末块补齐——顺序写反会得到长度相同但内容全错的密文
 * ============================================================ */
(function () {
  /* 复用主逻辑里的 AES 单块实现：aesExpandKey(key) → {w, Nr}，
     aesEncryptBlockJS(block, ks) / aesDecryptBlockJS(block, ks) 都是 16 字节进 16 字节出。 */
  function aesBlock(enc, key, b) {
    var ks = aesExpandKey(key);
    return enc ? aesEncryptBlockJS(b, ks) : aesDecryptBlockJS(b, ks);
  }
  function xtsMulAlpha(t) {
    /* GF(2^128) 乘 x：整体左移 1 位；最高字节的进位位（原 bit7）要异或 0x87 */
    var o = new Uint8Array(16), carry = 0, i;
    for (i = 0; i < 16; i++) {
      var v = t[i];
      o[i] = ((v << 1) | carry) & 0xff;
      carry = (v >> 7) & 1;
    }
    if (carry) o[0] ^= 0x87;
    return o;
  }
  function xor16(a, b) { var o = new Uint8Array(16); for (var i = 0; i < 16; i++) o[i] = a[i] ^ b[i]; return o; }

  function xtsCrypt(pt, key, tweakLe, encrypt) {
    var ks = key.length / 2, k1 = key.subarray(0, ks), k2 = key.subarray(ks);
    var T = aesBlock(true, k2, tweakLe);
    var out = new Uint8Array(pt.length);
    var n = Math.floor(pt.length / 16), rem = pt.length % 16;
    var i, j;
    if (rem === 0) {
      for (j = 0; j < n; j++) {
        var blk = pt.subarray(j * 16, j * 16 + 16);
        var x = xor16(blk, T);
        var y = aesBlock(encrypt, k1, x);
        for (i = 0; i < 16; i++) out[j * 16 + i] = y[i] ^ T[i];
        T = xtsMulAlpha(T);
      }
      return out;
    }
    /* ---- ciphertext stealing（IEEE 1619-2007 §5.3）：末块不足 16 字节 ----
       加密：CC = XTS(P_m, T_m)；PP = XTS(P_last ‖ CC[rem:], T_{m+1})
             输出 = 前 m 块密文 ‖ PP ‖ CC[:rem]
       解密：tmp = XTS⁻¹(PP, T_{m+1}) = P_last ‖ CC[rem:]
             CC = 密文尾 rem 字节 ‖ tmp[rem:]；P_m = XTS⁻¹(CC, T_m)
       ⚠ 末尾那 rem 字节是 CC 的【前】rem 字节，不是后 rem 字节——
         写反时长度完全正确、只有末块错，极易漏检。 */
    /* L=17 时 n=1、rem=1：第 0 块就是 P_m，残余 1 字节走 CTS，此时常规处理块数为 0。
       所以判据是 n < 1（连一个完整块都没有），不是 n < 2。 */
    if (n < 1) throw new Error('XTS 至少需要 16 字节（1 个完整块）');
    var m = n - 1;                                   /* 参与常规处理的完整块数 */
    for (j = 0; j < m; j++) {
      var blk2 = pt.subarray(j * 16, j * 16 + 16);
      var y2 = aesBlock(encrypt, k1, xor16(blk2, T));
      for (i = 0; i < 16; i++) out[j * 16 + i] = y2[i] ^ T[i];
      T = xtsMulAlpha(T);
    }
    var Tm1 = xtsMulAlpha(T);
    var pm = pt.subarray(m * 16, m * 16 + 16);
    var tail = pt.subarray((m + 1) * 16);            /* 残余 rem 字节 */
    if (encrypt) {
      var CC = aesBlock(true, k1, xor16(pm, T));
      for (i = 0; i < 16; i++) CC[i] ^= T[i];
      var ppIn = new Uint8Array(16);
      for (i = 0; i < rem; i++) ppIn[i] = tail[i];
      for (i = rem; i < 16; i++) ppIn[i] = CC[i];
      var PP = aesBlock(true, k1, xor16(ppIn, Tm1));
      for (i = 0; i < 16; i++) out[m * 16 + i] = PP[i] ^ Tm1[i];
      for (i = 0; i < rem; i++) out[(m + 1) * 16 + i] = CC[i];
    } else {
      var PPc = new Uint8Array(16);
      for (i = 0; i < 16; i++) PPc[i] = pm[i];       /* pm 在这里就是密文的倒数第二块 */
      var tmp = aesBlock(false, k1, xor16(PPc, Tm1));
      for (i = 0; i < 16; i++) tmp[i] ^= Tm1[i];     /* = P_last ‖ CC[rem:] */
      var CCfull = new Uint8Array(16);
      for (i = 0; i < rem; i++) CCfull[i] = tail[i]; /* 密文尾 rem 字节 = CC[:rem] */
      for (i = rem; i < 16; i++) CCfull[i] = tmp[i];
      var Pm_ = aesBlock(false, k1, xor16(CCfull, T));
      for (i = 0; i < 16; i++) out[m * 16 + i] = Pm_[i] ^ T[i];
      for (i = 0; i < rem; i++) out[(m + 1) * 16 + i] = tmp[i];
    }
    return out;
  }

  function parseTweak(p) {
    p = String(p == null ? '' : p).trim();
    var t = new Uint8Array(16);
    if (!p) return t;
    if (/^0x[0-9a-fA-F]+$/.test(p) || /^\d+$/.test(p)) {
      var v = BigInt(p);
      for (var i = 0; i < 16; i++) { t[i] = Number(v & 0xffn); v >>= 8n; }   /* 小端 */
      return t;
    }
    var b = hexToBytes(p.replace(/\s/g, ''));
    if (b.length > 16) throw new Error('tweak 最多 16 字节');
    var o = new Uint8Array(16);
    /* 作为扇区号（小端）填入 */
    for (var j = 0; j < b.length; j++) o[j] = b[b.length - 1 - j];
    return o;
  }
  function parseKey(k, want) {
    var b = hexToBytes(String(k || '').replace(/\s/g, ''));
    if (b.length !== want * 2) throw new Error('密钥需 ' + (want * 2) + ' 字节（XTS-' + (want * 8) + '：两个 ' + want + ' 字节子密钥）');
    return b;
  }

  var G = '对称加密';
  reg({ id: 'aes-xts-128', name: 'AES-XTS-128（磁盘扇区加密）', group: G, key: true, param: true,
    keyLabel: '密钥（32 字节 Hex = 两个 AES-128 子密钥）', paramLabel: '扇区号（十进制或 0x 前缀，如 0）', paramOptional: true,
    info: 'IEEE 1619 磁盘加密模式，BitLocker / FileVault / LUKS 使用。同一明文在不同扇区产生不同密文——这是它防"水印攻击"的关键。已与 OpenSSL（Python cryptography）交叉验证。',
    enc: function (b, k, p, fmt) { return bytesOut(xtsCrypt(b, parseKey(k, 16), parseTweak(p), true), fmt); },
    dec: function (s, k, p, fmt) { return bytesOut(xtsCrypt(bytesIn(String(s), fmt), parseKey(k, 16), parseTweak(p), false), fmt); } });

  reg({ id: 'aes-xts-256', name: 'AES-XTS-256（磁盘扇区加密）', group: G, key: true, param: true,
    keyLabel: '密钥（64 字节 Hex = 两个 AES-256 子密钥）', paramLabel: '扇区号（十进制或 0x 前缀，如 0）', paramOptional: true,
    info: 'AES-256 版本 XTS，密钥 64 字节。已与 OpenSSL（Python cryptography）交叉验证。',
    enc: function (b, k, p, fmt) { return bytesOut(xtsCrypt(b, parseKey(k, 32), parseTweak(p), true), fmt); },
    dec: function (s, k, p, fmt) { return bytesOut(xtsCrypt(bytesIn(String(s), fmt), parseKey(k, 32), parseTweak(p), false), fmt); } });

  globalThis.XTS = { xtsCrypt: xtsCrypt, xtsMulAlpha: xtsMulAlpha, parseTweak: parseTweak };
})();
