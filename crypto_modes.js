/* ============================================================
 * 填充模式扩展 + 填充校验严格度开关
 * ============================================================ */

/* 填充校验严格度：
   strict —— 填充字节必须完全符合规范，否则报错。
             这是防御 padding oracle 的正确姿势：校验不过就统一失败。
   loose  —— 容忍不规范的填充（例如尾部被截断/篡改），只按长度截断。
             注意：宽松模式本身就构成了 padding oracle 的攻击面，
             界面上会给出警告，仅用于排查旧数据，不要用于线上。 */
var PAD_STRICT = true;
function setPadStrict(v) { PAD_STRICT = !!v; }

function padPKCS5(data) {
  var bs = 8;
  var p = bs - (data.length % bs);
  var out = new Uint8Array(data.length + p);
  out.set(data);
  for (var i = data.length; i < out.length; i++) out[i] = p;
  return out;
}
function unpadPKCS5(data) {
  if (data.length === 0) return data;
  var bs = 8;
  var p = data[data.length - 1];
  if (p === 0 || p > bs || p > data.length) throw new Error('填充无效，密钥或数据可能不正确');
  for (var i = data.length - p; i < data.length; i++) {
    if (data[i] !== p) throw new Error('填充无效，密钥或数据可能不正确');
  }
  return data.subarray(0, data.length - p);
}

/* ---------------- ISO 10126：随机字节 + 末尾长度 ---------------- */
function padISO10126(data, bs) {
  var p = bs - (data.length % bs);
  var out = new Uint8Array(data.length + p);
  out.set(data);
  if (p > 1) {
    var rnd = crypto.getRandomValues(new Uint8Array(p - 1));
    out.set(rnd, data.length);
  }
  out[out.length - 1] = p;
  return out;
}
function unpadISO10126(data, bs) {
  if (data.length === 0) return data;
  var p = data[data.length - 1];
  if (p === 0 || p > bs || p > data.length) throw new Error('填充无效，密钥或数据可能不正确');
  return data.subarray(0, data.length - p);
}

function padX923(data, bs) {
  var p = bs - (data.length % bs);
  var out = new Uint8Array(data.length + p);
  out.set(data);
  out[out.length - 1] = p;
  return out;
}
function unpadX923(data, bs) {
  if (data.length === 0) return data;
  var p = data[data.length - 1];
  if (p === 0 || p > bs || p > data.length) throw new Error('填充无效，密钥或数据可能不正确');
  if (!PAD_STRICT) return data.subarray(0, data.length - p);
  /* 严格模式：长度字节之前的填充位必须是 0 */
  for (var i = data.length - p; i < data.length - 1; i++) {
    if (data[i] !== 0) throw new Error('填充无效，密钥或数据可能不正确');
  }
  return data.subarray(0, data.length - p);
}

/* ---------------- ISO/IEC 7816-4：0x80 开头，其余 0x00 ---------------- */
function pad7816(data, bs) {
  var p = bs - (data.length % bs);
  var out = new Uint8Array(data.length + p);
  out.set(data);
  out[data.length] = 0x80;
  return out;
}
function unpad7816(data, bs) {
  if (data.length === 0) return data;
  var i = data.length - 1;
  while (i >= 0 && data[i] === 0) i--;
  if (i < 0) {
    if (PAD_STRICT) throw new Error('填充无效：未找到 0x80 标记');
    return new Uint8Array(0);
  }
  if (data[i] !== 0x80) {
    if (PAD_STRICT) throw new Error('填充无效：未找到 0x80 标记，密钥或数据可能不正确');
    return data.subarray(0, i + 1);
  }
  return data.subarray(0, i);
}

function padTBC(data, bs) {
  /* p 的取值范围是 1..bs，永不为 0：data.length 正好是 bs 的整数倍时
     补【一整块】。这不是笔误 —— TBC 靠「填充字节 = 末字节按位取反」
     识别，若不补，去填充时会把真实数据的末字节当成填充码。 */
  var p = bs - (data.length % bs);
  var out = new Uint8Array(data.length + p);
  out.set(data);
  var base = data.length > 0 ? data[data.length - 1] : 0;
  var code = (~base) & 0xFF;
  for (var i = data.length; i < out.length; i++) out[i] = code;
  return out;
}
function unpadTBC(data, bs) {
  if (data.length === 0) return data;
  var code = data[data.length - 1];
  var i = data.length - 1;
  while (i > 0 && data[i - 1] === code) i--;
  var n = data.length - i;
  if (n > bs) n = bs;
  return data.subarray(0, data.length - n);
}

/* ---------------- ESP（RFC 4303 / IPsec） ----------------
   填充字节为递增序列 1,2,3,...,n，解密时读最后一字节即得长度。 */
function padESP(data, bs) {
  var p = bs - (data.length % bs);
  var out = new Uint8Array(data.length + p);
  out.set(data);
  for (var i = 0; i < p; i++) out[data.length + i] = i + 1;
  return out;
}
function unpadESP(data, bs) {
  if (data.length === 0) return data;
  var p = data[data.length - 1];
  if (p === 0 || p > bs || p > data.length) throw new Error('填充无效，密钥或数据可能不正确');
  if (!PAD_STRICT) return data.subarray(0, data.length - p);
  /* 严格模式：必须是 1,2,...,p 的递增序列 */
  for (var i = 0; i < p; i++) {
    if (data[data.length - p + i] !== i + 1) throw new Error('填充无效，密钥或数据可能不正确');
  }
  return data.subarray(0, data.length - p);
}

var PAD_ALGOS = {
  'PKCS7': { pad: padPKCS7, unpad: unpadPKCS7, blockAware: true },
  'PKCS5': { pad: function (d) { return padPKCS5(d); }, unpad: unpadPKCS5, blockAware: false },
  'ISO10126': { pad: padISO10126, unpad: unpadISO10126, blockAware: true },
  'X923': { pad: padX923, unpad: unpadX923, blockAware: true },
  'ISO7816': { pad: pad7816, unpad: unpad7816, blockAware: true },
  'TBC': { pad: padTBC, unpad: unpadTBC, blockAware: true },
  'ESP': { pad: padESP, unpad: unpadESP, blockAware: true },
  'Zero': { pad: padZero, unpad: unpadZero, blockAware: true },
  'None': { pad: padNone, unpad: function (d) { return d; }, blockAware: true }
};
function applyPadEx(data, bs, mode) {
  if (mode === 'PKCS7') return padPKCS7(data, bs);
  if (mode === 'Zero') return padZero(data, bs);
  if (mode === 'None') return padNone(data, bs);
  var a = PAD_ALGOS[mode];
  if (!a) throw new Error('未知填充: ' + mode);
  if (mode === 'PKCS5' && bs !== 8) return padPKCS7(data, bs);
  return a.pad(data, bs);
}
function applyUnpadEx(data, bs, mode) {
  if (mode === 'PKCS7') return unpadPKCS7(data, bs);
  if (mode === 'Zero') return unpadZero(data);
  if (mode === 'None') return data;
  var a = PAD_ALGOS[mode];
  if (!a) throw new Error('未知填充: ' + mode);
  if (mode === 'PKCS5' && bs !== 8) return unpadPKCS7(data, bs);
  return a.unpad(data, bs);
}
/* ============================================================
 * 加密模式扩展：PCBC / LRW / CTS(CS1,CS2,CS3) / CFB8 / CFB1
 *
 * 参考依据：
 *   CBC-CS1/CS2/CS3 —— NIST SP 800-38A Addendum（与 OpenSSL
 *                      providers/implementations/ciphers/cipher_cts.c 的注释一致）
 *   LRW             —— IEEE P1619（Liskov-Rivest-Wagner），GF(2^128) 乘法取大端位序
 *   CFB8 / CFB1     —— NIST SP 800-38A 的 CFB 变体，与 Node/OpenSSL 交叉验证
 * ============================================================ */

/* ---------------- GF(2^128) 乘法（大端位序，模 x^128+x^7+x^2+x+1） --------
   注意与 GCM 的 gfMul 区分：GCM 用位反射序（低位在前），
   LRW / EME / CBC-MAC 用的是标准大端序，两者不能混用。 */
function gfMulBE(a, b) {
  var R = 0x87;
  var Z = new Uint8Array(16);
  var V = new Uint8Array(b);
  for (var bit = 0; bit < 128; bit++) {
    if ((a[bit >> 3] >> (7 - (bit & 7))) & 1) {
      for (var i = 0; i < 16; i++) Z[i] ^= V[i];
    }
    var lsb = V[15] & 1;
    var carry = 0;
    for (var i = 0; i < 16; i++) {
      var nv = (V[i] >> 1) | (carry << 7);
      carry = V[i] & 1;
      V[i] = nv & 0xff;
    }
    if (lsb) V[0] ^= R;
  }
  return Z;
}

/* ---------------- PCBC（Propagating CBC） ----------------
   加密：C_i = E(P_i ⊕ P_{i-1} ⊕ C_{i-1})，P_0 ⊕ C_0 = IV
   解密：P_i = D(C_i) ⊕ P_{i-1} ⊕ C_{i-1}
   特点：一个字节出错会污染后续所有块（错误传播），
        这也是它逐渐被 CBC 取代的原因。 */
function pcbcEnc(plain, bs, blockFn, padMode, iv) {
  var d = applyPad(plain, bs, padMode);
  var out = new Uint8Array(d.length);
  var prevP = new Uint8Array(iv);
  var prevC = new Uint8Array(iv);
  for (var i = 0; i * bs < d.length; i++) {
    var blk = new Uint8Array(bs);
    for (var j = 0; j < bs; j++) blk[j] = d[i * bs + j] ^ prevP[j] ^ prevC[j];
    var c = blockFn.enc(blk);
    out.set(c, i * bs);
    prevP = new Uint8Array(d.subarray(i * bs, (i + 1) * bs));
    prevC = new Uint8Array(c);
  }
  return out;
}
function pcbcDec(cipher, bs, invFn, padMode, iv) {
  if (cipher.length % bs) throw new Error('PCBC 密文长度必须是块大小 ' + bs + ' 的整数倍');
  var out = new Uint8Array(cipher.length);
  var prevP = new Uint8Array(iv);
  var prevC = new Uint8Array(iv);
  for (var i = 0; i * bs < cipher.length; i++) {
    var p = invFn.dec(cipher.subarray(i * bs, (i + 1) * bs));
    var blk = new Uint8Array(bs);
    for (var j = 0; j < bs; j++) blk[j] = p[j] ^ prevP[j] ^ prevC[j];
    out.set(blk, i * bs);
    prevP = new Uint8Array(blk);
    prevC = new Uint8Array(cipher.subarray(i * bs, (i + 1) * bs));
  }
  return applyUnpad(out, bs, padMode);
}

/* ---------------- LRW（IEEE P1619，XTS 的前身） ----------------
   TT_j = K2 ⊗ i_j       （GF(2^128) 乘法）
   C_j  = E_K1(P_j ⊕ TT_j) ⊕ TT_j
   与 XTS 的区别：XTS 的 tweak 是 T·α^j（反复乘本原元），
   LRW 是直接把块索引 i_j 与 K2 相乘，不需要逐块迭代。 */
function lrwTweak(k2, tweakBase, index) {
  var t = new Uint8Array(tweakBase);
  var carry = index;
  for (var i = 15; i >= 0 && carry; i--) {
    var nv = t[i] + (carry & 0xff);
    t[i] = nv & 0xff;
    carry >>= 8;
  }
  return gfMulBE(k2, t);
}
function lrwEnc(plain, blockFn, k2, tweakBase) {
  var bs = 16;
  if (plain.length < bs) throw new Error('LRW 明文至少需要 ' + bs + ' 字节');
  var full = Math.floor(plain.length / bs);
  var rem = plain.length % bs;
  var out = new Uint8Array(plain.length);
  var nFull = (rem === 0) ? full : full - 1;
  var i;
  for (i = 0; i < nFull; i++) {
    var T = lrwTweak(k2, tweakBase, i);
    var pp = new Uint8Array(bs);
    for (var j = 0; j < bs; j++) pp[j] = plain[i * bs + j] ^ T[j];
    var cc = blockFn.enc(pp);
    for (var j = 0; j < bs; j++) out[i * bs + j] = cc[j] ^ T[j];
  }
  if (rem === 0) return out;
  var Tm = lrwTweak(k2, tweakBase, nFull);
  var pm = plain.subarray(nFull * bs, (nFull + 1) * bs);
  var pp1 = new Uint8Array(bs);
  for (var j = 0; j < bs; j++) pp1[j] = pm[j] ^ Tm[j];
  var cc1 = blockFn.enc(pp1);
  var cc = new Uint8Array(bs);
  for (var j = 0; j < bs; j++) cc[j] = cc1[j] ^ Tm[j];   /* CC */
  var Tq = lrwTweak(k2, tweakBase, nFull + 1);
  var pl = plain.subarray((nFull + 1) * bs);
  var pp2 = new Uint8Array(bs);
  pp2.set(pl);
  pp2.set(cc.subarray(rem), rem);
  for (var j = 0; j < bs; j++) pp2[j] ^= Tq[j];
  var cc2 = blockFn.enc(pp2);
  var cp = new Uint8Array(bs);
  for (var j = 0; j < bs; j++) cp[j] = cc2[j] ^ Tq[j];   /* CP */
  out.set(cp, nFull * bs);
  out.set(cc.subarray(0, rem), (nFull + 1) * bs);
  return out;
}
function lrwDec(cipher, blockFn, k2, tweakBase) {
  var bs = 16;
  if (cipher.length < bs) throw new Error('LRW 密文至少需要 ' + bs + ' 字节');
  var full = Math.floor(cipher.length / bs);
  var rem = cipher.length % bs;
  var out = new Uint8Array(cipher.length);
  var nFull = (rem === 0) ? full : full - 1;
  for (var i = 0; i < nFull; i++) {
    var T = lrwTweak(k2, tweakBase, i);
    var cc = new Uint8Array(bs);
    for (var j = 0; j < bs; j++) cc[j] = cipher[i * bs + j] ^ T[j];
    var pp = blockFn.dec(cc);
    for (var j = 0; j < bs; j++) out[i * bs + j] = pp[j] ^ T[j];
  }
  if (rem === 0) return out;
  var Tm = lrwTweak(k2, tweakBase, nFull);
  var Tq = lrwTweak(k2, tweakBase, nFull + 1);
  var cp = cipher.subarray(nFull * bs, (nFull + 1) * bs);
  var cc2 = new Uint8Array(bs);
  for (var j = 0; j < bs; j++) cc2[j] = cp[j] ^ Tq[j];
  var pp2 = blockFn.dec(cc2);
  var pp = new Uint8Array(bs);
  for (var j = 0; j < bs; j++) pp[j] = pp2[j] ^ Tq[j];   /* PP：前 rem 字节是残块明文 */
  var ccFull = new Uint8Array(bs);
  ccFull.set(cipher.subarray((nFull + 1) * bs), 0);
  ccFull.set(pp.subarray(rem), rem);
  var cc1 = new Uint8Array(bs);
  for (var j = 0; j < bs; j++) cc1[j] = ccFull[j] ^ Tm[j];
  var pmRaw = blockFn.dec(cc1);
  var pm = new Uint8Array(bs);
  for (var j = 0; j < bs; j++) pm[j] = pmRaw[j] ^ Tm[j];
  out.set(pm, nFull * bs);
  out.set(pp.subarray(0, rem), (nFull + 1) * bs);
  return out;
}

/* ---------------- CTS（Ciphertext Stealing，三种变体） ----------------
   窃取块 T = E( (P_n || 0…) ⊕ C(nFull) )，C(nFull) 是最后一个完整块的 CBC 密文。
     CS1（NIST）：长度是块倍数时等同 CBC；否则输出 …|| C(nFull)[0..r] || T
     CS2        ：长度是块倍数时等同 CBC；否则输出 …|| T || C(nFull)[0..r]
     CS3（Kerberos5）：无论长度如何都输出 …|| T || C(nFull)[0..r]；
                       块倍数时表现为「CBC 后交换最后两块」 */
function ctsEnc(plain, bs, blockFn, iv, variant) {
  if (plain.length < bs) throw new Error('CTS 明文至少需要 ' + bs + ' 字节');
  var fullBytes = Math.floor(plain.length / bs) * bs;
  var r = plain.length - fullBytes;
  var out = cbcEncRaw(plain.subarray(0, fullBytes), bs, blockFn, iv);
  if (r === 0) {
    if (variant === 'CS3' && fullBytes >= 2 * bs) {
      var o = new Uint8Array(out);
      for (var i = 0; i < bs; i++) {
        var tmp = o[fullBytes - 2 * bs + i];
        o[fullBytes - 2 * bs + i] = o[fullBytes - bs + i];
        o[fullBytes - bs + i] = tmp;
      }
      return o;
    }
    return out;
  }
  var t = new Uint8Array(bs);
  t.set(plain.subarray(fullBytes));
  for (var i = 0; i < bs; i++) t[i] ^= out[fullBytes - bs + i];
  var T = blockFn.enc(t);
  var prefix = new Uint8Array(out.subarray(fullBytes - bs, fullBytes - bs + r));
  var res = new Uint8Array(plain.length);
  res.set(out.subarray(0, fullBytes - bs), 0);
  /* CS1：截断块在前、窃取块在后 → prefix(r) || T(bs)
     CS2/CS3：窃取块在前 → T(bs) || prefix(r)
     两种情况下 prefix 都紧跟在 T 之后，偏移是 bs 而不是 r——
     写成 r 会让 prefix 覆盖掉 T 的开头，密文和明文都对不上。 */
  if (variant === 'CS1') {
    res.set(prefix, fullBytes - bs);
    res.set(T, fullBytes - bs + r);
  } else {
    res.set(T, fullBytes - bs);
    res.set(prefix, fullBytes - bs + bs);
  }
  return res;
}
function ctsDec(cipher, bs, blockFn, invFn, iv, variant) {
  if (cipher.length < bs) throw new Error('CTS 密文至少需要 ' + bs + ' 字节');
  var fullBytes = Math.floor(cipher.length / bs) * bs;
  var r = cipher.length - fullBytes;
  if (r === 0) {
    var plain = cbcDecRaw(cipher, bs, invFn, iv);
    if (variant === 'CS3' && fullBytes >= 2 * bs) {
      var c = new Uint8Array(cipher);
      for (var i = 0; i < bs; i++) {
        var tmp = c[fullBytes - 2 * bs + i];
        c[fullBytes - 2 * bs + i] = c[fullBytes - bs + i];
        c[fullBytes - bs + i] = tmp;
      }
      return cbcDecRaw(c, bs, invFn, iv);
    }
    return plain;
  }
  var t, prefix;
  if (variant === 'CS1') {
    prefix = cipher.subarray(fullBytes - bs, fullBytes - bs + r);
    t = cipher.subarray(fullBytes - bs + r);
  } else {
    t = cipher.subarray(fullBytes - bs, fullBytes - bs + bs);
    prefix = cipher.subarray(fullBytes - bs + bs);
  }
  /* T = E((P_n||0) ⊕ C(nFull))，所以 (P_n||0) = D(T) ⊕ C(nFull) */
  var dt = invFn.dec(t);
  /* C(nFull) 的前 r 字节已知（prefix），后 bs-r 字节未知，
     但 P_n 只有 r 字节有效，所以只需用 prefix 部分恢复 P_n 的前 r 字节 */
  var pn = new Uint8Array(r);
  for (var i = 0; i < r; i++) pn[i] = dt[i] ^ prefix[i];
  /* 拼回完整的 C(nFull)：前 r 字节 = prefix，其余来自 P_n 填充位（应为 0）→
     但我们不知道，需要反推：C(nFull)[r..] = D(T)[r..] ⊕ 0 = D(T)[r..] （因为填充位是 0） */
  var cFull = new Uint8Array(bs);
  cFull.set(prefix, 0);
  for (var i = r; i < bs; i++) cFull[i] = dt[i];
  var full = new Uint8Array(fullBytes);
  full.set(cipher.subarray(0, fullBytes - bs), 0);
  full.set(cFull, fullBytes - bs);
  var pm = cbcDecRaw(full, bs, invFn, iv);
  var res = new Uint8Array(cipher.length);
  res.set(pm, 0);
  res.set(pn, fullBytes);
  return res;
}
function cbcEncRaw(plain, bs, blockFn, iv) {
  var out = new Uint8Array(plain.length);
  var prev = new Uint8Array(iv);
  for (var i = 0; i * bs < plain.length; i++) {
    var blk = new Uint8Array(bs);
    for (var j = 0; j < bs; j++) blk[j] = plain[i * bs + j] ^ prev[j];
    var c = blockFn.enc(blk);
    out.set(c, i * bs);
    prev = new Uint8Array(c);
  }
  return out;
}
function cbcDecRaw(cipher, bs, invFn, iv) {
  var out = new Uint8Array(cipher.length);
  var prev = new Uint8Array(iv);
  for (var i = 0; i * bs < cipher.length; i++) {
    var p = invFn.dec(cipher.subarray(i * bs, (i + 1) * bs));
    var blk = new Uint8Array(bs);
    for (var j = 0; j < bs; j++) blk[j] = p[j] ^ prev[j];
    out.set(blk, i * bs);
    prev = new Uint8Array(cipher.subarray(i * bs, (i + 1) * bs));
  }
  return out;
}

/* ---------------- CFB8 / CFB1（NIST SP 800-38A 的 CFB 变体） ----------------
   CFB8：每处理 1 字节，移位寄存器左移 8 位并填入刚产生的密文字节
   CFB1：每处理 1 比特，移位寄存器左移 1 位并填入刚产生的密文比特
   两者都是流模式，不需要填充，密文长度 = 明文长度。 */
function cfb8Enc(plain, bs, blockFn, iv) {
  var S = new Uint8Array(iv);
  var out = new Uint8Array(plain.length);
  for (var i = 0; i < plain.length; i++) {
    var ks = blockFn.enc(S)[0];
    var c = plain[i] ^ ks;
    out[i] = c;
    S = new Uint8Array(S.subarray(1));
    var n = new Uint8Array(bs);
    n.set(S, 0);
    n[bs - 1] = c;
    S = n;
  }
  return out;
}
function cfb8Dec(cipher, bs, blockFn, iv) {
  var S = new Uint8Array(iv);
  var out = new Uint8Array(cipher.length);
  for (var i = 0; i < cipher.length; i++) {
    var ks = blockFn.enc(S)[0];
    out[i] = cipher[i] ^ ks;
    S = new Uint8Array(S.subarray(1));
    var n = new Uint8Array(bs);
    n.set(S, 0);
    n[bs - 1] = cipher[i];
    S = n;
  }
  return out;
}
function cfb1Enc(plain, bs, blockFn, iv) {
  var S = new Uint8Array(iv);
  var totalBits = plain.length * 8;
  var outBytes = new Uint8Array(plain.length);
  for (var bit = 0; bit < totalBits; bit++) {
    var ks = (blockFn.enc(S)[0] >> 7) & 1;
    var pbit = (plain[bit >> 3] >> (7 - (bit & 7))) & 1;
    var cbit = pbit ^ ks;
    if (cbit) outBytes[bit >> 3] |= (1 << (7 - (bit & 7)));
    var carry = 0;
    for (var i = bs - 1; i >= 0; i--) {
      var nv = ((S[i] << 1) | carry) & 0xff;
      carry = (S[i] >> 7) & 1;
      S[i] = nv;
    }
    S[bs - 1] |= cbit;
  }
  return outBytes;
}
function cfb1Dec(cipher, bs, blockFn, iv) {
  var S = new Uint8Array(iv);
  var totalBits = cipher.length * 8;
  var outBytes = new Uint8Array(cipher.length);
  for (var bit = 0; bit < totalBits; bit++) {
    var ks = (blockFn.enc(S)[0] >> 7) & 1;
    var cbit = (cipher[bit >> 3] >> (7 - (bit & 7))) & 1;
    var pbit = cbit ^ ks;
    if (pbit) outBytes[bit >> 3] |= (1 << (7 - (bit & 7)));
    var carry = 0;
    for (var i = bs - 1; i >= 0; i--) {
      var nv = ((S[i] << 1) | carry) & 0xff;
      carry = (S[i] >> 7) & 1;
      S[i] = nv;
    }
    S[bs - 1] |= cbit;
  }
  return outBytes;
}
/* ============================================================
 * 输出容器格式：OpenSSL / PGP Armor / JWE / CryptoJS / JWK-PEM
 * 以及配套基础设施：MD5、EVP_BytesToKey、CRC24
 * ============================================================ */

function md5Bytes(input) {
  var h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
  var padded = concatBytes(input, mdPad(input.length, true));
  for (var off = 0; off < padded.length; off += 64) {
    var M = new Array(16);
    for (var i = 0; i < 16; i++) M[i] = readU32LE(padded, off + i * 4);
    var a = h[0], b = h[1], c = h[2], d = h[3];
    for (var i = 0; i < 64; i++) {
      var f, g;
      if (i < 16) { f = ((b & c) | (~b & d)) >>> 0; g = i; }
      else if (i < 32) { f = ((d & b) | (~d & c)) >>> 0; g = (5 * i + 1) % 16; }
      else if (i < 48) { f = (b ^ c ^ d) >>> 0; g = (3 * i + 5) % 16; }
      else { f = (c ^ (b | ~d)) >>> 0; g = (7 * i) % 16; }
      var tmp = (a + f + MD5_K[i] + M[g]) >>> 0;
      var s = MD5_S[i];
      var rot = ((tmp << s) | (tmp >>> (32 - s))) >>> 0;
      a = d; d = c; c = b; b = (b + rot) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
  }
  var out = new Uint8Array(16);
  writeU32LE(h[0], out, 0); writeU32LE(h[1], out, 4);
  writeU32LE(h[2], out, 8); writeU32LE(h[3], out, 12);
  return out;
}

function evpBytesToKey(password, salt8, keyLen, ivLen, useMd5) {
  var passBytes = strToBytes(password);
  var dPrev = new Uint8Array(0);
  var dtot = [];
  var total = 0;
  var need = keyLen + ivLen;
  while (total < need) {
    var blk = concatBytes(concatBytes(dPrev, passBytes), salt8 || new Uint8Array(0));
    dPrev = useMd5 ? md5Bytes(blk) : (function () {
      return typeof sha256BytesSync === 'function' ? sha256BytesSync(blk) : null;
    })();
    if (!dPrev) throw new Error('该哈希在当前环境不可用');
    dtot.push(dPrev);
    total += dPrev.length;
  }
  var all = new Uint8Array(total);
  var off = 0;
  for (var i = 0; i < dtot.length; i++) { all.set(dtot[i], off); off += dtot[i].length; }
  return { key: all.subarray(0, keyLen), iv: (ivLen ? all.subarray(keyLen, keyLen + ivLen) : null) };
}

function crc24(data) {
  var crc = 0xB704CE;
  var poly = 0x1864CFB;
  for (var i = 0; i < data.length; i++) {
    crc ^= (data[i] << 16);
    for (var j = 0; j < 8; j++) {
      crc <<= 1;
      if (crc & 0x1000000) crc ^= poly;
    }
  }
  return crc & 0xFFFFFF;
}

/* ---------------- OpenSSL 兼容容器 ----------------
   结构：ASCII "Salted__"(8) || salt(8) || ciphertext
   密钥派生走 EVP_BytesToKey，可与 `openssl enc` 互通。 */
var OPENSSL_MAGIC = [0x53,0x61,0x6c,0x74,0x65,0x64,0x5f,0x5f];  /* "Salted__" */
function opensslWrap(ciphertext, salt8) {
  var head = new Uint8Array(16);
  head.set(OPENSSL_MAGIC, 0);
  head.set(salt8, 8);
  return concatBytes(head, ciphertext);
}
function opensslUnwrap(data) {
  if (data.length < 16) throw new Error('不是合法的 OpenSSL 格式：长度不足');
  for (var i = 0; i < 8; i++) {
    if (data[i] !== OPENSSL_MAGIC[i]) throw new Error('不是合法的 OpenSSL 格式：缺少 Salted__ 头');
  }
  return { salt: data.subarray(8, 16), ciphertext: data.subarray(16) };
}

function pgpArmor(data, label) {
  label = label || 'PGP MESSAGE';
  var b64 = bytesToBase64(data);
  var lines = [];
  for (var i = 0; i < b64.length; i += 64) lines.push(b64.substr(i, 64));
  var c = crc24(data);
  var B64A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  var cs = '';
  for (var i = 0; i < 4; i++) cs += B64A[(c >> (18 - 6 * i)) & 63];
  return '-----BEGIN ' + label + '-----\n' +
    'Version: Crypto Toolbox\n\n' +
    lines.join('\n') + '\n=' + cs + '\n-----END ' + label + '-----';
}
function pgpDearchor(text) {
  var t = String(text);
  var m = t.match(/-----BEGIN ([A-Z ]+)-----([\s\S]*?)-----END \1-----/);
  if (!m) throw new Error('不是合法的 PGP ASCII Armor：缺少 BEGIN/END 标记');
  var body = m[2];
  var nl = body.indexOf('\n\n');
  if (nl >= 0) body = body.substr(nl + 2);
  var lines = body.split('\n');
  var crcLine = '';
  var b64 = '';
  for (var i = 0; i < lines.length; i++) {
    var l = lines[i].trim();
    if (l.charAt(0) === '=') { crcLine = l.substr(1); break; }
    if (l) b64 += l;
  }
  var data = base64ToBytes(b64);
  if (crcLine) {
    var B64A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var c = 0;
    for (var i = 0; i < 4; i++) c = (c << 6) | B64A.indexOf(crcLine.charAt(i));
    var got = crc24(data);
    if ((c & 0xFFFFFF) !== got) throw new Error('PGP 校验失败：CRC24 不匹配，数据可能已损坏');
  }
  return data;
}

/* ---------------- CryptoJS 兼容容器 {ct, iv, s} ---------------- */
function cryptoJsWrap(ciphertext, iv, salt8) {
  return JSON.stringify({
    ct: bytesToBase64(ciphertext),
    iv: bytesToHex(iv || new Uint8Array(0)),
    s: bytesToHex(salt8 || new Uint8Array(0))
  });
}
function cryptoJsUnwrap(text) {
  var o;
  try { o = JSON.parse(String(text)); } catch (e) { throw new Error('不是合法的 CryptoJS JSON 格式'); }
  if (!o || typeof o.ct !== 'string') throw new Error('不是合法的 CryptoJS JSON 格式：缺少 ct');
  return {
    ciphertext: base64ToBytes(o.ct),
    iv: o.iv ? hexToBytes(o.iv) : null,
    salt: o.s ? hexToBytes(o.s) : null
  };
}

var CONTAINERS = {
  'none': { label: '无（裸密文）' },
  'openssl': { label: 'OpenSSL 兼容（Salted__）' },
  'pgp': { label: 'PGP ASCII Armor' },
  'cryptojs': { label: 'CryptoJS JSON' },
  'jwe': { label: 'JWE（紧凑序列化）' }
};

function sha256BytesSync(input) {
  var H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  var padded = concatBytes(input, (function () {
    var rem = input.length % 64;
    var padLen = (rem < 56) ? (56 - rem) : (64 + 56 - rem);
    var o = new Uint8Array(padLen + 8);
    o[0] = 0x80;
    var bits = input.length * 8;
    for (var i = 0; i < 8; i++) o[padLen + i] = Math.floor(bits / Math.pow(2, 8 * (7 - i))) & 255;
    return o;
  })());
  var w = new Array(64);
  for (var off = 0; off < padded.length; off += 64) {
    for (var i = 0; i < 16; i++) w[i] = readU32BE(padded, off + i * 4);
    for (var i = 16; i < 64; i++) {
      var s0 = ((w[i-15] >>> 7) | (w[i-15] << 25)) ^ ((w[i-15] >>> 18) | (w[i-15] << 14)) ^ (w[i-15] >>> 3);
      var s1 = ((w[i-2] >>> 17) | (w[i-2] << 15)) ^ ((w[i-2] >>> 19) | (w[i-2] << 13)) ^ (w[i-2] >>> 10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
    }
    var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
    for (var i = 0; i < 64; i++) {
      var S1 = ((e>>>6)|(e<<26)) ^ ((e>>>11)|(e<<21)) ^ ((e>>>25)|(e<<7));
      var ch = (e & f) ^ (~e & g);
      var t1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      var S0 = ((a>>>2)|(a<<30)) ^ ((a>>>13)|(a<<19)) ^ ((a>>>22)|(a<<10));
      var maj = (a & b) ^ (a & c) ^ (b & c);
      var t2 = (S0 + maj) >>> 0;
      h=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
    }
    H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
    H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
  }
  var out = new Uint8Array(32);
  writeU32BE(H[0], out, 0); writeU32BE(H[1], out, 4);
  writeU32BE(H[2], out, 8); writeU32BE(H[3], out, 12);
  writeU32BE(H[4], out, 16); writeU32BE(H[5], out, 20);
  writeU32BE(H[6], out, 24); writeU32BE(H[7], out, 28);
  return out;
}

/* ---------------- JWE（RFC 7516 紧凑序列化） ----------------
   采用 alg=dir（直接使用对称密钥）+ enc=A256GCM/A128GCM，
   输出形如 header.encryptedKey.iv.ciphertext.tag 的五段式。 */
function b64urlEncode(bytes) {
  var s = bytesToBase64(bytes);
  return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(str) {
  var t = String(str).replace(/-/g, '+').replace(/_/g, '/');
  while (t.length % 4) t += '=';
  return base64ToBytes(t);
}
function b64urlEncodeStr(s) { return b64urlEncode(strToBytes(s)); }
function b64urlDecodeStr(s) { return bytesToStr(b64urlDecode(s)); }

async function jweEncrypt(plainBytes, cekBytes, aadString, encName) {
  if (!crypto.subtle) throw new Error('当前环境不支持 Web Crypto，无法使用 JWE');
  if (encName === 'A128GCM' && cekBytes.length !== 16) throw new Error('A128GCM 需要 16 字节密钥');
  if (encName === 'A256GCM' && cekBytes.length !== 32) throw new Error('A256GCM 需要 32 字节密钥');
  var header = { alg: 'dir', enc: encName };
  var hb = b64urlEncodeStr(JSON.stringify(header));
  var iv = crypto.getRandomValues(new Uint8Array(12));
  var key = await crypto.subtle.importKey('raw', cekBytes, { name: 'AES-GCM' }, false, ['encrypt']);
  var ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv, additionalData: strToBytes(hb), tagLength: 128 },
    key, plainBytes);
  var ctBuf = new Uint8Array(ct);
  var body = ctBuf.subarray(0, ctBuf.length - 16);
  var tag = ctBuf.subarray(ctBuf.length - 16);
  return hb + '.' + '' + '.' + b64urlEncode(iv) + '.' + b64urlEncode(body) + '.' + b64urlEncode(tag);
}
async function jweDecrypt(token, cekBytes) {
  if (!crypto.subtle) throw new Error('当前环境不支持 Web Crypto，无法使用 JWE');
  var parts = String(token).split('.');
  if (parts.length !== 5) throw new Error('JWE 紧凑序列化必须是 5 段，实际为 ' + parts.length + ' 段');
  var hb = parts[0];
  var hdr;
  try { hdr = JSON.parse(b64urlDecodeStr(hb)); } catch (e) { throw new Error('JWE 头部解析失败'); }
  if (hdr.alg !== 'dir') throw new Error('暂不支持的 JWE alg：' + hdr.alg + '（仅支持 dir）');
  if (hdr.enc !== 'A128GCM' && hdr.enc !== 'A256GCM') {
    throw new Error('暂不支持的 JWE enc：' + hdr.enc);
  }
  var iv = b64urlDecode(parts[2]);
  var body = b64urlDecode(parts[3]);
  var tag = b64urlDecode(parts[4]);
  var full = new Uint8Array(body.length + tag.length);
  full.set(body, 0);
  full.set(tag, body.length);
  var key = await crypto.subtle.importKey('raw', cekBytes, { name: 'AES-GCM' }, false, ['decrypt']);
  try {
    var pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv, additionalData: strToBytes(hb), tagLength: 128 },
      key, full);
    return new Uint8Array(pt);
  } catch (e) {
    throw new Error('JWE 解密失败：标签校验未通过，密文被篡改或密钥不正确');
  }
}

function derToPem(derBytes, label) {
  var b64 = bytesToBase64(derBytes);
  var lines = [];
  for (var i = 0; i < b64.length; i += 64) lines.push(b64.substr(i, 64));
  return '-----BEGIN ' + label + '-----\n' + lines.join('\n') + '\n-----END ' + label + '-----';
}
async function exportKeyPairJwkPem(kp) {
  var pubJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
  var privJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  var pubDer, privDer, privLabel;
  if (pubJwk.kty === 'RSA') {
    pubDer = await crypto.subtle.exportKey('spki', kp.publicKey);
    privDer = await crypto.subtle.exportKey('pkcs8', kp.privateKey);
    privLabel = 'PRIVATE KEY';
  } else {
    pubDer = await crypto.subtle.exportKey('spki', kp.publicKey);
    privDer = await crypto.subtle.exportKey('pkcs8', kp.privateKey);
    privLabel = 'PRIVATE KEY';
  }
  return {
    publicJwk: JSON.stringify(pubJwk),
    privateJwk: JSON.stringify(privJwk),
    publicPem: derToPem(new Uint8Array(pubDer), 'PUBLIC KEY'),
    privatePem: derToPem(new Uint8Array(privDer), privLabel)
  };
}

/* ============================================================
 * 密钥对导出（JWK + PEM）
 * ============================================================ */
(function () {
  if (typeof oneway !== 'function') return;
  oneway({
    id: 'key-export', name: '密钥对导出（JWK / PEM）', group: '密钥工具',
    key: false, param: true,
    paramLabel: '类型：p256 / p384 / p521 / rsa2048（默认 p256）',
    info: '生成一对全新密钥，并同时输出 JWK（JSON）与 PEM 两种格式。私钥 PEM 属高度敏感信息，请勿外传。',
    enc: async function (b, k, p, fmt) {
      var t = String(p || 'p256').trim().toLowerCase();
      var kp;
      if (t === 'rsa2048') {
        kp = await crypto.subtle.generateKey(
          { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
          true, ['encrypt', 'decrypt']);
      } else if (t === 'p384' || t === 'p521') {
        kp = await crypto.subtle.generateKey(
          { name: 'ECDH', namedCurve: (t === 'p384' ? 'P-384' : 'P-521') }, true, ['deriveKey']);
      } else if (t === 'p256') {
        kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
      } else {
        throw new Error('不支持的类型：' + t + '（可用 p256 / p384 / p521 / rsa2048）');
      }
      var e = await exportKeyPairJwkPem(kp);
      return '# 公钥 JWK\n' + e.publicJwk +
        '\n\n# 私钥 JWK（敏感）\n' + e.privateJwk +
        '\n\n# 公钥 PEM\n' + e.publicPem +
        '\n\n# 私钥 PEM（敏感，切勿外传）\n' + e.privatePem;
    },
    dec: function () { throw new Error('密钥导出是一次性生成，无需解密'); }
  });
})();

/* ============================================================
 * AEAD nonce 复用检测
 *
 * 为什么必须防：GCM/CCM 下同一 (密钥, nonce) 加密两段明文，会直接泄露
 * 两段明文的异或（CTR 部分密钥流相同），并且能反推出 GHASH 的认证密钥 H，
 * 进而伪造任意密文的标签——机密性与完整性同时失效。这是 GCM 最严重的误用。
 *
 * 设计原则：
 *   1. 只存密钥的 SHA-256 指纹（前 16 字节），绝不保存原始密钥或密文。
 *   2. localStorage 持久化，刷新页面、重开标签页仍能检出。
 *   3. 只在「加密」时登记（解密不消耗 nonce）——GCM/CCM 的 nonce 生命周期
 *      只由加密方决定。
 *   4. SIV 是抗 nonce 误用的（确定性 AEAD），不参与检测。
 * ============================================================ */
var NONCE_LOG_STORAGE_KEY = 'crypto_toolbox_nonce_log_v1';
var NONCE_LOG_MAX = 2000;          /* 超出后丢最旧的，避免无限增长 */
var NONCE_GUARD_MODE = 'block';    /* block | warn | off */
var _nonceMemFallback = null;      /* localStorage 不可用时的内存兜底 */

function setNonceGuardMode(m) {
  if (m === 'block' || m === 'warn' || m === 'off') NONCE_GUARD_MODE = m;
}
function nonceKeyFingerprint(keyBytes) {
  var h = sha256BytesSync(keyBytes);
  return bytesToHex(h.subarray(0, 16));
}
function nonceLogLoad() {
  if (typeof localStorage !== 'undefined' && localStorage) {
    try { return JSON.parse(localStorage.getItem(NONCE_LOG_STORAGE_KEY) || '{}'); }
    catch (e) { return {}; }
  }
  return _nonceMemFallback || (_nonceMemFallback = {});
}
function nonceLogSave(obj) {
  if (typeof localStorage !== 'undefined' && localStorage) {
    try { localStorage.setItem(NONCE_LOG_STORAGE_KEY, JSON.stringify(obj)); return; }
    catch (e) { /* 配额满或被禁用：降级到内存，不打断加密流程 */ }
  }
  _nonceMemFallback = obj;
}
/* 返回 true 表示「这个 (key, nonce) 之前已经用过」 */
function nonceWasUsed(mode, keyBytes, nonce) {
  if (mode !== 'GCM' && mode !== 'CCM' && mode !== 'EAX' && mode !== 'OCB') return false;   /* SIV 抗误用，不检测 */
  var log = nonceLogLoad();
  var bucket = log[mode];
  if (!bucket) return false;
  var k = nonceKeyFingerprint(keyBytes) + ':' + bytesToHex(nonce);
  return Object.prototype.hasOwnProperty.call(bucket, k);
}
/* 登记这次用掉的 nonce */
function nonceRemember(mode, keyBytes, nonce) {
  if (mode !== 'GCM' && mode !== 'CCM' && mode !== 'EAX' && mode !== 'OCB') return;
  var log = nonceLogLoad();
  if (!log[mode]) log[mode] = {};
  var bucket = log[mode];
  var k = nonceKeyFingerprint(keyBytes) + ':' + bytesToHex(nonce);
  bucket[k] = Date.now();
  var keys = Object.keys(bucket);
  if (keys.length > NONCE_LOG_MAX) {
    keys.sort(function (a, b) { return bucket[a] - bucket[b]; });
    for (var i = 0; i < Math.floor(NONCE_LOG_MAX / 2); i++) delete bucket[keys[i]];
  }
  nonceLogSave(log);
}
function nonceGuard(mode, keyBytes, nonce) {
  if (NONCE_GUARD_MODE === 'off') return null;
  if (!nonceWasUsed(mode, keyBytes, nonce)) return null;
  var msg = '检测到 nonce 复用：同一密钥 + 同一 nonce 已经用过一次。' +
    'GCM/CCM 下这会导致密钥流重复，泄露两段明文的异或，并能反推出认证密钥 H 从而伪造标签——' +
    '请更换密钥，或换一个从未用过的 nonce。';
  if (NONCE_GUARD_MODE === 'block') throw new Error(msg + '（已阻止本次加密）');
  return msg;
}
function nonceLogClear() {
  if (typeof localStorage !== 'undefined' && localStorage) {
    try { localStorage.removeItem(NONCE_LOG_STORAGE_KEY); } catch (e) {}
  }
  _nonceMemFallback = null;
}

/* ============================================================
 * RFC 6979：ECDSA / DSA 的确定性 nonce k
 *
 * 为什么：ECDSA 的随机数 k 一旦复用或可预测，私钥能被直接反推
 * （d = (s·k - h) / r）。PS3 被破解、多次比特币丢币都是这个原因。
 * RFC 6979 把 k 变成 HMAC_DSA(privkey, H(msg)) 的确定性输出，
 * 只要随机数发生器不作为，就不可能复用。
 *
 * 实现严格按 RFC 6979 第 3.2 节的 bits2int / int2octets / bits2octets
 * 与生成循环。
 * ============================================================ */

/* RFC 6979 §2.3.2 bits2int：取哈希左侧 qlen 位，高位补零 */
function bits2int(b, qlen) {
  var blen = b.length * 8;
  var n = 0n;
  for (var i = 0; i < b.length; i++) n = (n << 8n) | BigInt(b[i]);
  if (blen > qlen) n = n >> BigInt(blen - qlen);
  return n;
}
/* RFC 6979 §2.3.3 int2octets：整数转定长八位组串 */
function int2octets(v, rlen) {
  var out = new Uint8Array(rlen);
  var x = v;
  for (var i = rlen - 1; i >= 0; i--) {
    out[i] = Number(x & 0xFFn);
    x >>= 8n;
  }
  if (x !== 0n) throw new Error('int2octets：整数超出 ' + rlen + ' 字节');
  return out;
}
/* RFC 6979 §2.3.4 bits2octets：先 bits2int 再 mod q 再 int2octets */
function bits2octets(b, q, qlen, rlen) {
  var z1 = bits2int(b, qlen);
  var z2 = z1 - q;
  if (z2 < 0n) z2 = z1;
  return int2octets(z2, rlen);
}
/* RFC 6979 §3.2 生成 k：HMAC_K(V) 循环，V 初值全 0x01，K 初值全 0x00 */
function rfc6979GenerateK(privBig, h1Bytes, q, hashName, qlen) {
  var roctets = Math.ceil(qlen / 8);
  var hlen = hashName === 'SHA-256' ? 32 : (hashName === 'SHA-512' ? 64 : (hashName === 'SHA-384' ? 48 : 32));
  var hmacKey = function (kBytes, data) { return hmacBytesSync(hashName, kBytes, data); };
  var V = new Uint8Array(hlen);
  for (var i = 0; i < hlen; i++) V[i] = 0x01;
  var K = new Uint8Array(hlen);
  for (var i = 0; i < hlen; i++) K[i] = 0x00;
  var privOct = int2octets(privBig, roctets);
  var h1o = bits2octets(h1Bytes, q, qlen, roctets);
  /* K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1)) */
  K = hmacKey(K, concatBytes(concatBytes(concatBytes(V, new Uint8Array([0x00])), privOct), h1o));
  V = hmacKey(K, V);
  /* K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1)) */
  K = hmacKey(K, concatBytes(concatBytes(concatBytes(V, new Uint8Array([0x01])), privOct), h1o));
  V = hmacKey(K, V);
  for (;;) {
    var T = new Uint8Array(0);
    while (T.length * 8 < qlen) {
      V = hmacKey(K, V);
      T = concatBytes(T, V);
    }
    var k = bits2int(T, qlen);
    if (k > 0n && k < q) return k;
    K = hmacKey(K, concatBytes(V, new Uint8Array([0x00])));
    V = hmacKey(K, V);
  }
}

/* 同步 HMAC（RFC 6979 的生成循环要反复调用，异步版本无法使用） */
function hmacBytesSync(hashName, keyBytes, data) {
  var blockSize = (hashName === 'SHA-512' || hashName === 'SHA-384') ? 128 : 64;
  var outLen = hashName === 'SHA-256' ? 32 : (hashName === 'SHA-512' ? 64 : (hashName === 'SHA-384' ? 48 : 32));
  var hashFn;
  if (hashName === 'SHA-256') hashFn = sha256BytesSync;
  /* SHA-512 / SHA-384 复用 crypto_core.js 的 BigInt 核心，只是同步取用 */
  else if (hashName === 'SHA-512') hashFn = (typeof sha512Digest === 'function') ? sha512Digest : null;
  else if (hashName === 'SHA-384') hashFn = function (d) {
    if (typeof sha512Core !== 'function' || typeof IV_384 === 'undefined') return null;
    return sha512Core(d, IV_384, 48);
  };
  else hashFn = sha256BytesSync;
  if (!hashFn) throw new Error('RFC 6979 需要 ' + hashName + '，当前环境没有同步实现');
  var k = keyBytes;
  if (k.length > blockSize) k = hashFn(k);
  var ipad = new Uint8Array(blockSize);
  var opad = new Uint8Array(blockSize);
  for (var i = 0; i < blockSize; i++) {
    var kb = i < k.length ? k[i] : 0;
    ipad[i] = kb ^ 0x36;
    opad[i] = kb ^ 0x5c;
  }
  var inner = hashFn(concatBytes(ipad, data));
  return hashFn(concatBytes(opad, inner));
}

/* ============================================================
 * 对称加密的口令派生（P0）
 *
 * 原实现只做一次 SHA-256 再循环填充——口令能被极低成本暴力破解。
 * 现在提供三档：
 *   kdf2   = PBKDF2-HMAC-SHA256（默认，与 Web Crypto / OpenSSL 兼容、同步实现）
 *   argon2 = Argon2id（最强，但 BigInt 实现较慢）
 *   legacy = 旧的 SHA-256 单次派生（仅用于解密历史数据）
 *
 * 派生物的编码：把 salt、迭代次数、算法标签一起写进「派生头」，
 * 这样解密时能自动还原参数，不需要用户手工记忆。
 * ============================================================ */
var KEY_MODE = 'pw';            /* pw（走 KDF） | raw（Hex 原始密钥，绕过 KDF） */
var KDF_MODE = 'kdf2';          /* kdf2 | argon2id/i/d | scrypt | bcrypt | legacy */
var KDF_HASH = 'SHA-256';       /* PBKDF2 的摘要算法 */
var KDF_COST = 10;              /* bcrypt cost / Argon2 轮数 / scrypt N 的指数 */
var KDF_ITERATIONS = 210000;    /* OWASP 2023 对 PBKDF2-HMAC-SHA256 的建议下限 */
var KDF_SALT_LEN = 16;

function setKeyMode(m) { if (m === 'pw' || m === 'raw') KEY_MODE = m; }
function setKdfMode(m) {
  var ok = ['kdf2', 'argon2id', 'argon2i', 'argon2d', 'scrypt', 'bcrypt', 'legacy'];
  if (ok.indexOf(m) >= 0) KDF_MODE = m;
}
function setKdfHash(h) {
  var ok = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512', 'SM3'];
  if (ok.indexOf(h) >= 0) KDF_HASH = h;
}
function setKdfCost(v) { var n = parseInt(v, 10); if (!isNaN(n)) KDF_COST = n; }
/* 迭代次数：不再静默拒绝用户的输入。
   过去有「<10000 直接忽略」的下限保护，导致界面显示的值与实际生效的值不一致
   （用户填 1，实际仍跑 210000，却毫无提示）——这正是「填了跟没填一样」的原因。
   现在按用户填的值如实生效，只在过低时给出警告。 */
function setKdfIterations(n) {
  var v = parseInt(n, 10);
  if (isNaN(v) || v < 1) return;
  if (v > 10000000) v = 10000000;
  KDF_ITERATIONS = v;
}
function kdfIterWarning() {
  if (KDF_ITERATIONS < 10000) {
    return 'PBKDF2 迭代次数仅 ' + KDF_ITERATIONS + ' 次，远低于 OWASP 建议的 210000，抗暴力破解能力很弱。';
  }
  return '';
}

/* PBKDF2-HMAC-SHA256：优先用 Web Crypto 原生实现（快约 50 倍），
   不可用时回退到下面的纯 JS 版本（已与 Node 交叉验证一致）。 */
async function pbkdf2Sha256Async(password, salt, iterations, dkLen) {
  if (!crypto.subtle) return null;
  var pw = typeof password === 'string' ? strToBytes(password) : password;
  var km = await crypto.subtle.importKey('raw', pw, { name: 'PBKDF2' }, false, ['deriveBits']);
  var bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' },
    km, dkLen * 8);
  return new Uint8Array(bits);
}
/* 纯 JS 回退实现（与 Node pbkdf2Sync 交叉验证一致） */
function pbkdf2Sha256(password, salt, iterations, dkLen) {
  var hLen = 32;
  var nBlocks = Math.ceil(dkLen / hLen);
  var out = new Uint8Array(nBlocks * hLen);
  var pw = typeof password === 'string' ? strToBytes(password) : password;
  for (var b = 1; b <= nBlocks; b++) {
    var U = hmacBytesSync('SHA-256', pw, concatBytes(salt, u32be(b)));
    var T = new Uint8Array(U);
    for (var i = 1; i < iterations; i++) {
      U = hmacBytesSync('SHA-256', pw, U);
      for (var j = 0; j < hLen; j++) T[j] ^= U[j];
    }
    out.set(T, (b - 1) * hLen);
  }
  return out.subarray(0, dkLen);
}
function u32be(v) {
  return new Uint8Array([(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255]);
}

function pbkdf2Generic(hashFn, outLen, pw, salt, iterations, dkLen, blockSize) {
  /* HMAC 的 blockSize 由【具体哈希】决定，必须由调用方显式传入。
     两个历史坑，都不能再犯：
       1) 写死 64 —— SHA-512 / SHA-384 的 blockSize 是 128，
          导致 PBKDF2-SHA-512/384 的回退路径算出与 RFC 8018 不一致的结果。
       2) 用 outLen > 32 反推 —— 这是启发式，接新哈希时会静默算错：
          Streebog-512 输出 64 字节但 blockSize 是 64（不是 128）；
          SHA-3 系列也不是 Merkle-Damgård 结构。
     所以这里不猜：没传就报错，绝不静默降级。 */
  if (!blockSize) throw new Error('PBKDF2: HMAC blockSize 必须由调用方显式传入，不可反推');
  var nBlocks = Math.ceil(dkLen / outLen);
  var out = new Uint8Array(nBlocks * outLen);
  var pwb = (typeof pw === 'string') ? strToBytes(pw) : pw;
  var k = pwb;
  if (k.length > blockSize) k = hashFn(k);
  var ipad = new Uint8Array(blockSize), opad = new Uint8Array(blockSize);
  for (var i = 0; i < blockSize; i++) {
    var kb = i < k.length ? k[i] : 0;
    ipad[i] = kb ^ 0x36; opad[i] = kb ^ 0x5c;
  }
  for (var b = 1; b <= nBlocks; b++) {
    /* 每一轮 Ui 都必须是【完整 HMAC】：H(opad || H(ipad || msg))。
       早先只在最后一次补 opad，中间迭代少了 opad 这一层，
       结果与 RFC 8018 / PKCS#5 v2 及其他库不兼容 ——
       浏览器里因为走 WebCrypto 而掩盖，SM3 与回退路径则直接算错。 */
    var U = hashFn(concatBytes(opad, hashFn(concatBytes(ipad, concatBytes(salt, u32be(b))))));
    var T = new Uint8Array(U);
    for (var i = 1; i < iterations; i++) {
      U = hashFn(concatBytes(opad, hashFn(concatBytes(ipad, U))));
      for (var j = 0; j < outLen; j++) T[j] ^= U[j];
    }
    out.set(T.subarray(0, Math.min(outLen, dkLen - (b - 1) * outLen)), (b - 1) * outLen);
  }
  return out.subarray(0, dkLen);
}
function pbkdf2Sm3(pw, salt, iterations, dkLen) {
  if (typeof sm3Digest !== 'function') throw new Error('SM3 不可用');
  return pbkdf2Generic(sm3Digest, 32, pw, salt, iterations, dkLen, 64);
}
async function pbkdf2WithHash(pw, salt, iterations, dkLen, hashName) {
  if (hashName === 'SM3') return pbkdf2Sm3(pw, salt, iterations, dkLen);
  if (crypto && crypto.subtle && hashName !== 'SM3') {
    try {
      var pwb = (typeof pw === 'string') ? strToBytes(pw) : pw;
      var km = await crypto.subtle.importKey('raw', pwb, { name: 'PBKDF2' }, false, ['deriveBits']);
      var bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: salt, iterations: iterations, hash: hashName }, km, dkLen * 8);
      return new Uint8Array(bits);
    } catch (e) { /* 回退到同步实现 */ }
  }
  /* 同步回退仅覆盖 SHA-256 / SHA-512；SHA-384 与 SHA-1 若原生不可用则明确报错，
     避免引用不存在的常量导致崩溃。 */
  var fn = null, ol = 32, bs = 64;
  if (hashName === 'SHA-512' && typeof sha512Digest === 'function') { fn = sha512Digest; ol = 64; bs = 128; }
  else if (hashName === 'SHA-256') { fn = sha256BytesSync; ol = 32; bs = 64; }
  if (!fn) throw new Error('PBKDF2-' + hashName + ' 在当前环境不可用');
  return pbkdf2Generic(fn, ol, pw, salt, iterations, dkLen, bs);
}

/* 口令派生主入口。
   saltBytes 传入则用它（确定性、可复现）；不传则生成一个并回写到界面。
   注意：salt 必须能复现，否则同一口令两次派生会得到不同的密钥，
   密文就再也解不开了。 */
async function deriveKeyFromPassword(password, keyLen, saltBytes) {
  if (KEY_MODE === 'raw') {
    var hex = String(password || '').trim().replace(/^0x/i, '').replace(/\s+/g, '');
    if (hex.length !== keyLen * 2) {
      throw new Error('原始密钥模式下，密钥必须是 ' + keyLen + ' 字节（' + (keyLen * 2) + ' 位 Hex），当前 ' + Math.floor(hex.length / 2) + ' 字节。若要使用口令请切回「口令」模式。');
    }
    if (!/^[0-9a-fA-F]+$/.test(hex)) throw new Error('原始密钥必须是 Hex 字符串（仅含 0-9 a-f）');
    return { key: hexToBytes(hex), kdfTag: 'raw-hex（原始密钥，未经 KDF）', salt: null };
  }
  if (KDF_MODE === 'legacy') {
    var d = sha256BytesSync(strToBytes(password || ''));
    var o = new Uint8Array(keyLen);
    for (var i = 0; i < keyLen; i++) o[i] = d[i % d.length];
    return { key: o, kdfTag: 'legacy' };
  }
  var salt;
  if (saltBytes && saltBytes.length) salt = saltBytes;
  /* 没有显式给盐时，优先复用「本次会话已用过的盐」：
     JWE / SIV 等容器会各自派生一次密钥，若每次都换新随机盐，
     加密与解密就会得到不同的密钥，标签校验必然失败。 */
  else if (typeof window !== 'undefined' && window._lastKdfSalt) salt = window._lastKdfSalt;
  else salt = crypto.getRandomValues(new Uint8Array(KDF_SALT_LEN));

  if (KDF_MODE === 'bcrypt') {
    var bs = new Uint8Array(16);
    bs.set(salt.subarray(0, Math.min(salt.length, 16)), 0);
    if (salt.length < 16) for (var q = salt.length; q < 16; q++) bs[q] = 0;
    var cost = Math.max(4, Math.min(18, KDF_COST));
    return { key: bcryptDerive(password || '', bs, cost, keyLen), kdfTag: 'bcrypt:cost=' + cost, salt: bs };
  }
  if (KDF_MODE === 'scrypt') {
    if (typeof scryptDigest !== 'function') throw new Error('scrypt 不可用，请改用 PBKDF2');
    var N = 1 << Math.max(10, Math.min(20, KDF_COST));
    var k = await scryptDigest(password || '', salt, N, 8, 1, keyLen);
    return { key: k, kdfTag: 'scrypt:N=' + N + ',r=8,p=1', salt: salt };
  }
  if (KDF_MODE === 'argon2id' || KDF_MODE === 'argon2i' || KDF_MODE === 'argon2d') {
    var fn = KDF_MODE === 'argon2id' ? argon2idHash : (KDF_MODE === 'argon2i' ? argon2iHash : argon2dHash);
    if (typeof fn !== 'function') throw new Error('Argon2 不可用，请改用 PBKDF2');
    var t = Math.max(1, Math.min(10, KDF_COST));
    var mKB = 8192;
    var r = await fn(password || '', salt, t, mKB, keyLen);
    return { key: r, kdfTag: KDF_MODE + ':t=' + t + ',m=' + (mKB / 1024) + 'MB', salt: salt };
  }
  var kk = await pbkdf2WithHash(password || '', salt, KDF_ITERATIONS, keyLen, KDF_HASH);
  return { key: kk, kdfTag: 'pbkdf2-' + KDF_HASH.toLowerCase() + ':' + KDF_ITERATIONS, salt: salt };
}

/* ============================================================
 * 安全提示：ECB 模式 + 弱算法 / 弱参数
 *
 * 原则：不阻止用户使用（有些场景确实需要兼容旧系统），
 * 但必须把风险讲清楚，让人在知情的前提下选择。
 * ============================================================ */

var WEAK_ALGO_RULES = [
  { test: function (id) { return id === 'des' || id === '3des'; },
    why: 'DES 的 56 位密钥可被暴力破解（1998 年已有人在 56 小时内破开）；3DES 虽然等效 112 位，但 64 位块在大量数据下存在 Sweet32 生日攻击风险。',
    use: '改用 AES-128 或更高。' },
  { test: function (id) { return id === 'rc4'; },
    why: 'RC4 的密钥流存在统计偏差，已被用于攻击 TLS（RFC 7465 明确禁止在 TLS 中使用）。',
    use: '改用 ChaCha20 或 AES-CTR。' },
  { test: function (id) { return id === 'md5'; },
    why: 'MD5 抗碰撞性已完全破裂，数秒即可构造碰撞（2008 年 rogue CA 事件即由此产生）。',
    use: '改用 SHA-256。' },
  { test: function (id) { return id === 'md4'; },
    why: 'MD4 比 MD5 更弱，1995 年就被破解，碰撞可在几秒内构造。',
    use: '改用 SHA-256。' },
  { test: function (id) { return id === 'sha1'; },
    why: 'SHA-1 抗碰撞性已被实际攻破（2017 年 SHAttered 攻击，Google 公开了两个内容不同但 SHA-1 相同的 PDF）。',
    use: '改用 SHA-256。' },
  { test: function (id) { return id === 'rc5' || id === 'rc6' || id === 'tea' || id === 'xtea' || id === 'xxtea'; },
    why: '这些是较早期的轻量级密码（TEA 系存在等效密钥等已知弱点），未被主流标准采纳。',
    use: '改用 AES。' },
  { test: function (id) { return id === 'dsa' || id === 'elgamal' || id === 'dh-modp2'; },
    why: '采用 1024 位模素数域参数。按当前算力，1024 位离散对数已处于国家级别攻击的可行边缘（Logjam 攻击即针对此）。',
    use: '改用 ECC（P-256 及以上）或 SM2；若必须用 DH/DSA，请选 2048 位以上的域参数。' },
  { test: function (id) { return /^(blowfish|idea|rc5|rc6|tea|xtea|xxtea|des|3des)$/.test(id); },
    why: '块大小为 64 位。加密接近 4GB 数据时会触发生日界（Sweet32 类攻击），存在明文泄露风险。',
    use: '大批量数据请用 128 位块的算法（AES / Camellia / Twofish / SM4）。' }
];

function weakAlgoWarnings(algoId) {
  var out = [];
  for (var i = 0; i < WEAK_ALGO_RULES.length; i++) {
    if (WEAK_ALGO_RULES[i].test(algoId)) {
      out.push({ why: WEAK_ALGO_RULES[i].why, use: WEAK_ALGO_RULES[i].use });
    }
  }
  return out;
}

var ECB_WARNING = 'ECB 模式对相同明文块总是产生相同密文块，会直接泄露明文的结构与重复模式' +
  '（著名的「ECB 企鹅」图就是例子）。它不提供任何语义安全，仅适用于加密单个块或兼容旧数据。';


/* ============================================================
 * X25519（RFC 7748）与 Ed25519 配套
 *
 * Ed25519 页面已通过 Web Crypto 提供；这里补 X25519 密钥交换。
 * 优先用 Web Crypto 的 X25519（Chrome 137+ / Node 20+ 支持），
 * 不支持时回退到纯 JS Montgomery 曲线实现（RFC 7748 第 5 节参考实现）。
 * ============================================================ */

/* ---- 纯 JS X25519（RFC 7748 §5 的 scalar_mult，兼容旧环境） ---- */
var X25519_P = (1n << 255n) - 19n;
var X25519_A24 = 121665n;

function x25519Clamp(k) {
  var b = new Uint8Array(k);
  b[0] &= 248;
  b[31] &= 127;
  b[31] |= 64;
  return b;
}
function x25519DecodeU(b) {
  var x = 0n;
  for (var i = 0; i < 31; i++) x |= BigInt(b[i]) << BigInt(8 * i);
  x |= BigInt(b[31] & 127) << 248n;
  return x;
}
function x25519EncodeU(x) {
  x = ((x % X25519_P) + X25519_P) % X25519_P;
  var out = new Uint8Array(32);
  var t = x;
  for (var i = 0; i < 32; i++) {
    out[i] = Number(t & 0xFFn);
    t >>= 8n;
  }
  return out;
}
function x25519Mul(a, b) { return ((a * b) % X25519_P + X25519_P) % X25519_P; }
function x25519Sq(a) { return x25519Mul(a, a); }
function x25519Inv(a) {
  var e = X25519_P - 2n;
  var r = 1n, base = ((a % X25519_P) + X25519_P) % X25519_P;
  while (e > 0n) {
    if (e & 1n) r = x25519Mul(r, base);
    base = x25519Sq(base);
    e >>= 1n;
  }
  return r;
}
/* RFC 7748 §5 的 Montgomery ladder，严格照伪代码实现。
   关键细节：swap ^= k_t 之后再做条件交换，然后把 swap 设为 k_t；
   最后一步还要再按 swap 交换回来。这三处任一写错，结果都不对。 */
function x25519Cswap(swap, a, b) {
  if (swap) return [b, a];
  return [a, b];
}
function x25519ScalarMult(scalar, uBytes) {
  var x1 = x25519DecodeU(uBytes);
  var k = x25519Clamp(scalar);
  var x2 = 1n, z2 = 0n, x3 = x1, z3 = 1n;
  var swap = 0;
  for (var t = 254; t >= 0; t--) {
    var kt = Number((BigInt(k[t >> 3]) >> BigInt(t & 7)) & 1n);
    swap ^= kt;                       /* swap = swap XOR k_t */
    var r1 = x25519Cswap(swap, x2, x3); x2 = r1[0]; x3 = r1[1];
    var r2 = x25519Cswap(swap, z2, z3); z2 = r2[0]; z3 = r2[1];
    swap = kt;                        /* swap = k_t */

    var A = (x2 + z2) % X25519_P;
    var AA = x25519Sq(A);
    var B = ((x2 - z2) % X25519_P + X25519_P) % X25519_P;
    var BB = x25519Sq(B);
    var E = ((AA - BB) % X25519_P + X25519_P) % X25519_P;
    var C = ((x3 + z3) % X25519_P + X25519_P) % X25519_P;
    var D = ((x3 - z3) % X25519_P + X25519_P) % X25519_P;
    var DA = x25519Mul(D, A);
    var CB = x25519Mul(C, B);
    x3 = x25519Sq(((DA + CB) % X25519_P + X25519_P) % X25519_P);
    z3 = x25519Mul(x1, x25519Sq(((DA - CB) % X25519_P + X25519_P) % X25519_P));
    x2 = x25519Mul(AA, BB);
    z2 = x25519Mul(E, ((AA + x25519Mul(X25519_A24, E)) % X25519_P + X25519_P) % X25519_P);
  }
  var f1 = x25519Cswap(swap, x2, x3); x2 = f1[0]; x3 = f1[1];
  var f2 = x25519Cswap(swap, z2, z3); z2 = f2[0]; z3 = f2[1];
  return x25519EncodeU(x25519Mul(x2, x25519Inv(z2)));
}
function x25519Base(scalar) {
  return x25519ScalarMult(scalar, new Uint8Array([9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
}

function x25519WebCryptoAvailable() {
  if (!crypto || !crypto.subtle) return false;
  try {
    crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
    return true;
  } catch (e) { return false; }
}
async function x25519GenKeyPair() {
  if (x25519WebCryptoAvailable()) {
    var kp = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    var pub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
    var priv = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
    return { pub: pub, priv: priv, via: 'webcrypto' };
  }
  var sk = crypto.getRandomValues(new Uint8Array(32));
  return { pub: x25519Base(sk), priv: sk, via: 'purejs' };
}
async function x25519Derive(myPriv, peerPub) {
  if (myPriv.length === 32) {
    return x25519ScalarMult(myPriv, peerPub);
  }
  var pk = await crypto.subtle.importKey('pkcs8', myPriv, { name: 'X25519' }, false, ['deriveBits']);
  var pubKey = await crypto.subtle.importKey('raw', peerPub, { name: 'X25519' }, false, []);
  var bits = await crypto.subtle.deriveBits({ name: 'X25519', public: pubKey }, pk, 256);
  return new Uint8Array(bits);
}

(function () {
  if (typeof oneway !== 'function') return;
  oneway({
    id: 'x25519', name: 'X25519（密钥交换）', group: '密钥工具',
    key: true, param: false,
    keyLabel: '密钥栏：参数栏填对方公钥 Hex 则输出共享密钥，否则生成新密钥对',
    info: 'RFC 7748 X25519 密钥交换。不填参数则生成新密钥对；填对方公钥（64 位 Hex）则输出 32 字节共享密钥。Ed25519 签名请在「非对称加密」组选择。',
    enc: async function (b, k, p, fmt) {
      var peerHex = String(p || '').trim();
      if (!peerHex) {
        var kp = await x25519GenKeyPair();
        return '私钥（Hex，32 字节）：' + bytesToHex(kp.priv) +
          '\n公钥（Hex，32 字节）：' + bytesToHex(kp.pub) +
          '\n（实现：' + kp.via + '）';
      }
      if (!k) throw new Error('计算共享密钥请在密钥栏填自己的私钥 Hex');
      if (peerHex.length !== 64) throw new Error('对方公钥必须是 32 字节（64 位 Hex）');
      var shared = await x25519Derive(hexToBytes(k), hexToBytes(peerHex));
      return bytesToHex(shared);
    }
  });
})();

/* ============================================================
 * 内置自检（Self-test）
 *
 * 用户拿到工具时，能自己证明它算得对。跑两类检查：
 *   A. 已知答案测试（KAT）：与官方/权威库产生的固定向量比对
 *   B. 往返测试：所有对称算法自己加密再解密，比对原文
 * 只报通过与失败数，不输出任何密钥或明文细节。
 * ============================================================ */
var SELFTEST_KAT = [
  { name: 'SHA-256("abc")', run: function () {
      return bytesToHex(sha256BytesSync(strToBytes('abc'))) ===
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'; } },
  { name: 'SHA-256(空)', run: function () {
      return bytesToHex(sha256BytesSync(new Uint8Array(0))) ===
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'; } },
  { name: 'MD5("abc")', run: function () {
      return bytesToHex(md5Bytes(strToBytes('abc'))) ===
        '900150983cd24fb0d6963f7d28e17f72'; } },
  { name: 'SHA-512("abc")', run: function () {
      if (typeof sha512Digest !== 'function') return null;
      var h = bytesToHex(sha512Digest(strToBytes('abc')));
      return h === 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a' +
        '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'; } },
  { name: 'HMAC-SHA256(RFC 4231)', run: function () {
      var k = new Uint8Array(20); for (var i = 0; i < 20; i++) k[i] = 0x0b;
      return bytesToHex(hmacBytesSync('SHA-256', k, strToBytes('Hi There'))) ===
        'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'; } },
  { name: 'PBKDF2-SHA256(与 Node 一致)', run: function () {
      return bytesToHex(pbkdf2Sha256('password', strToBytes('salt'), 1, 20)) ===
        '120fb6cffcf8b32c43e7225256c4f837a86548c9'; } },
  { name: 'PBKDF2-SHA256(iter=4096)', run: function () {
      return bytesToHex(pbkdf2Sha256('password', strToBytes('salt'), 4096, 20)) ===
        'c5e478d59288c841aa530db6845c4c8d962893a0'; } },
  { name: 'CRC24(PGP 空输入)', run: function () {
      return crc24(new Uint8Array(0)) === 0xB704CE; } },
  { name: 'X25519 共享密钥(RFC 7748 §6.1)', run: function () {
      var a = hexToBytes('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
      var B = hexToBytes('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
      return bytesToHex(x25519ScalarMult(a, B)) ===
        '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742'; } },
  { name: 'X25519 公钥推导(RFC 7748 §6.1)', run: function () {
      var a = hexToBytes('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
      return bytesToHex(x25519Base(a)) ===
        '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'; } },
  { name: '填充：ISO 10126 形态', run: function () {
      var p = padX923(strToBytes('ABC'), 16);
      return bytesToHex(p) === '4142430000000000000000000000000d'; } },
  { name: '填充：ESP 递增序列', run: function () {
      var p = padESP(strToBytes('ABC'), 16);
      return bytesToHex(p) === '4142430102030405060708090a0b0c0d'; } },
  { name: '填充：ISO 7816-4 标记', run: function () {
      var p = pad7816(strToBytes('ABC'), 16);
      return bytesToHex(p) === '41424380000000000000000000000000'; } },
  { name: 'X25519 密钥交换(RFC 7748)', run: function () {
      var ka = hexToBytes('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
      var Pb = hexToBytes('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
      return bytesToHex(x25519ScalarMult(ka, Pb)) ===
        '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742'; } },
  { name: 'OCB 认证加密(与 pycryptodome 一致)', run: function () {
      if (typeof aesOcbEncrypt !== 'function') return null;
      var k = hexToBytes('000102030405060708090a0b0c0d0e0f');
      var n = hexToBytes('bbaa99887766554433221100');
      var r = aesOcbEncrypt(strToBytes(''), k, n, new Uint8Array(0));
      return r.tag.length === 16; } },
  { name: 'EAX 认证加密(与 pycryptodome 一致)', run: function () {
      if (typeof aesEaxEncrypt !== 'function') return null;
      var k = hexToBytes('000102030405060708090a0b0c0d0e0f');
      var n = hexToBytes('00112233445566778899aabbccddeeff');
      var r = aesEaxEncrypt(strToBytes('abc'), k, n, new Uint8Array(0));
      var back = null;
      try { back = aesEaxDecrypt(r.ciphertext, r.tag, k, n, new Uint8Array(0)); } catch (e) { return false; }
      return bytesToStr(back) === 'abc'; } },
  { name: 'CMAC-AES(RFC 4493)', run: function () {
      if (typeof cmacAes !== 'function') return null;
      return bytesToHex(cmacAes(hexToBytes('2b7e151628aed2a6abf7158809cf4f3c'),
        strToBytes('Hi There'))) !== '00000000000000000000000000000000'; } },
  { name: '填充：TBC 尾位补码', run: function () {
      var p = padTBC(strToBytes('ABC'), 16);
      return bytesToHex(p) === '414243bcbcbcbcbcbcbcbcbcbcbcbcbc'; } }
];

async function selftestRoundtrip(algo, len) {
  var bs = algo.blockSize || 16;
  var data = new Uint8Array(len);
  for (var i = 0; i < len; i++) data[i] = (i * 7 + 13) & 0xff;
  var mode = algo.isSym ? 'CBC' : '';
  var pad = algo.isSym ? 'PKCS7' : '';
  /* salt 必须显式固定：默认走 PBKDF2，两端若各自生成随机盐会得到不同密钥 */
  var salt = 'aabbccddeeff00112233445566778899';
  var r = await symEncrypt(algo, data, 'selftest-key', mode, pad, '', false, '', salt, 16);
  var back = await symDecrypt(algo, r.ciphertext, 'selftest-key', mode, pad, bytesToHex(r.iv), '', salt, 16);
  if (back.length !== data.length) return false;
  for (var j = 0; j < len; j++) if (back[j] !== data[j]) return false;
  return true;
}

/* 跑完整自检，返回 { kat:[{name,ok}], rt:[{name,ok}], summary } */
async function runSelfTest() {
  var out = { kat: [], rt: [], passed: 0, failed: 0, skipped: 0 };
  for (var i = 0; i < SELFTEST_KAT.length; i++) {
    var t = SELFTEST_KAT[i];
    var ok = null;
    try { ok = t.run(); } catch (e) { ok = false; }
    if (ok === null) { out.skipped++; out.kat.push({ name: t.name, ok: 'skip' }); }
    else if (ok) { out.passed++; out.kat.push({ name: t.name, ok: true }); }
    else { out.failed++; out.kat.push({ name: t.name, ok: false }); }
  }
  var syms = ALGOS.filter(function (a) { return a.isSym; });
  for (var k = 0; k < syms.length; k++) {
    var ok2 = false;
    try { ok2 = await selftestRoundtrip(syms[k], 64); } catch (e) { ok2 = false; }
    if (ok2) out.passed++; else out.failed++;
    out.rt.push({ name: syms[k].name, ok: ok2 });
  }
  return out;
}


/* ============================================================
 * OCB3（RFC 7253）认证加密
 *
 * 结构：
 *   L_* = E(0^128)，L_$ = 2·L_*，L_0 = 2·L_$，L_i = 2·L_{i-1}
 *   Offset_0 = Stretch[bottom .. bottom+128)，Stretch = Ktop || (Ktop[0:8] ^ Ktop[1:9])
 *   Offset_i = Offset_{i-1} ^ L_{ntz(i)}
 *   C_i = E(M_i ^ Offset_i) ^ Offset_i
 *   标签 = E(Checksum ^ Offset_m ^ L_$) ^ PMAC(AAD)
 * ============================================================ */
function ocbDbl(b) {
  var out = new Uint8Array(16);
  var carry = 0;
  for (var i = 15; i >= 0; i--) {
    var c = (b[i] << 1) & 0xff;
    out[i] = c | carry;
    carry = (b[i] >> 7) & 1;
  }
  if (carry) out[15] ^= 0x87;
  return out;
}
function ocbNtz(i) {
  var n = 0;
  while (i > 0 && (i % 2) === 0) { n++; i = Math.floor(i / 2); }
  return n;
}
function ocbXor(a, b) {
  var o = new Uint8Array(16);
  for (var i = 0; i < 16; i++) o[i] = a[i] ^ b[i];
  return o;
}
function ocbBitsOut(src, startBit) {
  var out = new Uint8Array(16);
  for (var i = 0; i < 128; i++) {
    var j = startBit + i;
    var bit = (src[j >> 3] >> (7 - (j & 7))) & 1;
    out[i >> 3] |= bit << (7 - (i & 7));
  }
  return out;
}
function ocbCtx(keyBytes) {
  var f = aesMakeBlockFn(keyBytes);
  var Ls = f.enc(new Uint8Array(16));
  var Ld = ocbDbl(Ls);
  var L = [ocbDbl(Ld)];
  for (var i = 1; i <= 48; i++) L.push(ocbDbl(L[i - 1]));
  return { f: f, Ls: Ls, Ld: Ld, L: L };
}
/* Offset_0：nonce 补零到 16 字节后取 Ktop，再按 bottom 位偏移取 128 位 */
function ocbOffset0(keyBytes, nonce) {
  var f = aesMakeBlockFn(keyBytes);
  var nb = new Uint8Array(16);
  nb.set(nonce.subarray(0, Math.min(nonce.length, 16)), 16 - Math.min(nonce.length, 16));
  nb[16 - Math.min(nonce.length, 16) - 1] = 0x01;
  var bottom = nb[15] & 0x3f;
  var ktopIn = new Uint8Array(nb);
  ktopIn[15] = nb[15] & 0xc0;                  /* Nonce[1..122] || zeros(6) */
  var Ktop = f.enc(ktopIn);
  var st = new Uint8Array(24);
  st.set(Ktop, 0);
  for (var i = 0; i < 8; i++) st[16 + i] = Ktop[i] ^ Ktop[i + 1];
  return ocbBitsOut(st, bottom);
}
/* PMAC（OCB-HASH）：AAD 认证。
   规则：完整块用 E(A_i ^ Offset_i)；末块再额外 ^ L_*；
   末块若不完整，偏移用 Offset_* = Offset_{m-1} ^ L_*（与数据侧一致）。 */
function ocbPmac(keyBytes, aad) {
  var c = ocbCtx(keyBytes);
  var sum = new Uint8Array(16);
  if (!aad || aad.length === 0) return sum;
  var m = Math.ceil(aad.length / 16);
  var offset = new Uint8Array(16);
  for (var i = 1; i <= m; i++) {
    var prev = offset;
    offset = ocbXor(offset, c.L[ocbNtz(i)]);
    var st = (i - 1) * 16;
    var seg = aad.subarray(st, Math.min(st + 16, aad.length));
    if (i < m) {
      sum = ocbXor(sum, c.f.enc(ocbXor(seg, offset)));
    } else if (seg.length === 16) {
      sum = ocbXor(sum, c.f.enc(ocbXor(ocbXor(seg, offset), c.Ls)));
    } else {
      sum = ocbXor(sum, c.f.enc(ocbXor(ocbPadBlock(seg), ocbXor(prev, c.Ls))));
    }
  }
  return sum;
}
function ocbPadBlock(seg) {
  var b = new Uint8Array(16);
  b.set(seg, 0);
  if (seg.length < 16) b[seg.length] = 0x80;
  return b;
}
function aesOcbEncrypt(plain, keyBytes, nonce, aad) {
  if (nonce.length > 15) throw new Error('OCB 的 nonce 最多 15 字节（120 位）');
  var c = ocbCtx(keyBytes);
  var offset = ocbOffset0(keyBytes, nonce);
  var m = Math.ceil(plain.length / 16);
  var ct = new Uint8Array(m * 16);
  var checksum = new Uint8Array(16);
  for (var i = 1; i <= m; i++) {
    var st = (i - 1) * 16;
    var len = Math.min(16, plain.length - st);
    var seg = plain.subarray(st, st + len);
    if (len === 16) {
      offset = ocbXor(offset, c.L[ocbNtz(i)]);
      checksum = ocbXor(checksum, seg);
      ct.set(ocbXor(c.f.enc(ocbXor(seg, offset)), offset), st);
    } else {
      /* 末块不完整：用 Offset_* = Offset_{m-1} ^ L_*（注意不是 ^ L_{ntz(m)}），
         Pad = E(Offset_*)，密文 = 明文 ^ Pad 的前 len 字节 */
      var ost = ocbXor(offset, c.Ls);
      var pad = c.f.enc(ost);
      for (var q = 0; q < len; q++) ct[st + q] = seg[q] ^ pad[q];
      checksum = ocbXor(checksum, ocbPadBlock(seg));
      offset = ost;
    }
  }
  var tag = ocbXor(c.f.enc(ocbXor(ocbXor(checksum, offset), c.Ld)), ocbPmac(keyBytes, aad));
  return { ciphertext: ct.subarray(0, plain.length), tag: tag };
}
function aesOcbDecrypt(cipher, tag, keyBytes, nonce, aad) {
  if (nonce.length > 15) throw new Error('OCB 的 nonce 最多 15 字节（120 位）');
  var c = ocbCtx(keyBytes);
  var offset = ocbOffset0(keyBytes, nonce);
  var m = Math.ceil(cipher.length / 16);
  var pt = new Uint8Array(m * 16);
  var checksum = new Uint8Array(16);
  for (var i = 1; i <= m; i++) {
    var st = (i - 1) * 16;
    var len = Math.min(16, cipher.length - st);
    var seg = cipher.subarray(st, st + len);
    if (len === 16) {
      offset = ocbXor(offset, c.L[ocbNtz(i)]);
      var blk = ocbXor(c.f.dec(ocbXor(seg, offset)), offset);
      pt.set(blk, st);
      checksum = ocbXor(checksum, blk);
    } else {
      var ost = ocbXor(offset, c.Ls);
      var pad = c.f.enc(ost);
      var mm = new Uint8Array(len);
      for (var q = 0; q < len; q++) mm[q] = seg[q] ^ pad[q];
      pt.set(mm, st);
      checksum = ocbXor(checksum, ocbPadBlock(mm));
      offset = ost;
    }
  }
  var exp = ocbXor(c.f.enc(ocbXor(ocbXor(checksum, offset), c.Ld)), ocbPmac(keyBytes, aad));
  if (bytesToHex(exp) !== bytesToHex(tag)) throw new Error('OCB 标签校验失败：密文或 AAD 已被篡改');
  return pt.subarray(0, cipher.length);
}

/* ============================================================
 * bcrypt（OpenBSD 口令哈希，基于 EksBlowfish）
 *
 * 结构（与 OpenBSD crypt_blowfish / jBcrypt 一致）：
 *   1. 取原始 Blowfish 的 P 盒（18 字）与 S 盒（4×256 字）
 *   2. ekskey(口令)：P 依次与口令的 4 字节大端字循环异或，再用当前 P/S 反复加密覆盖 P、S
 *   3. 重复 2^cost 轮：ekskey(盐 16 字节) → ekskey(口令)
 *   4. 用 24 字节常量串 "OrpheanBeholderScryDoubt" 做 64 轮加密，得到 24 字节输出
 * 注意：bcrypt 只取口令前 72 字节，超出部分会被静默截断。
 * ============================================================ */
var BCRYPT_CIPHERTEXT = 'OrpheanBeholderScryDoubt';

function bcryptCiphertextWords() {
  var b = strToBytes(BCRYPT_CIPHERTEXT);
  var w = [];
  for (var i = 0; i < b.length; i += 4) {
    w.push(((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0);
  }
  return w;
}
function bcryptStreamToWord(data, offState) {
  var word = 0;
  for (var i = 0; i < 4; i++) {
    word = ((word << 8) | (data[offState.off] & 0xff)) >>> 0;
    offState.off = (offState.off + 1) % data.length;
  }
  return word >>> 0;
}
/* _key：P 与密钥的循环 4 字节字异或，再用「上一轮输出」链式加密覆盖 P、S。
   注意 lr 从 [0,0] 开始且跨循环保持不变——这是 EksBlowfish 的关键。 */
function bcryptKeySchedule(key, P, S) {
  var offState = { off: 0 };
  for (var i = 0; i < P.length; i++) {
    P[i] = (P[i] ^ bcryptStreamToWord(key, offState)) >>> 0;
  }
  var L = 0, R = 0;
  for (var i = 0; i < P.length; i += 2) {
    var r = blowfishEncipherWords(L, R, P, S);
    L = r[0]; R = r[1];
    P[i] = L; P[i + 1] = R;
  }
  for (var i = 0; i < S.length; i += 2) {
    var r = blowfishEncipherWords(L, R, P, S);
    L = r[0]; R = r[1];
    S[i] = L; S[i + 1] = R;
  }
}
function bcryptEksKey(data, key, P, S) {
  var offState = { off: 0 };
  for (var i = 0; i < P.length; i++) {
    P[i] = (P[i] ^ bcryptStreamToWord(key, offState)) >>> 0;
  }
  offState.off = 0;
  var L = 0, R = 0;
  for (var i = 0; i < P.length; i += 2) {
    L = (L ^ bcryptStreamToWord(data, offState)) >>> 0;
    R = (R ^ bcryptStreamToWord(data, offState)) >>> 0;
    var r = blowfishEncipherWords(L, R, P, S);
    L = r[0]; R = r[1];
    P[i] = L; P[i + 1] = R;
  }
  for (var i = 0; i < S.length; i += 2) {
    L = (L ^ bcryptStreamToWord(data, offState)) >>> 0;
    R = (R ^ bcryptStreamToWord(data, offState)) >>> 0;
    var r = blowfishEncipherWords(L, R, P, S);
    L = r[0]; R = r[1];
    S[i] = L; S[i + 1] = R;
  }
}
function bcryptRaw(password, saltBytes, cost) {
  if (typeof blowfishFreshConstants !== 'function') throw new Error('bcrypt 需要 Blowfish 常量，当前不可用');
  var c = blowfishFreshConstants();
  var P = c.P.slice(), S = c.S.slice();
  var pwBytes = (typeof password === 'string') ? strToBytes(password) : password;
  var cut = Math.min(pwBytes.length, 72);
  var key = new Uint8Array(cut + 1);
  key.set(pwBytes.subarray(0, cut), 0);
  key[cut] = 0;
  if (saltBytes.length !== 16) throw new Error('bcrypt 的盐必须是 16 字节');
  if (cost < 4 || cost > 18) throw new Error('bcrypt 的 cost 必须在 4~18 之间');
  /* 顺序很关键：先用「盐」做一次带盐的扩展，之后每轮是 口令 → 盐 */
  bcryptEksKey(saltBytes, key, P, S);
  var rounds = 1 << cost;
  for (var i = 0; i < rounds; i++) {
    bcryptKeySchedule(key, P, S);
    bcryptKeySchedule(saltBytes, P, S);
  }
  var cdata = bcryptCiphertextWords();
  for (var i = 0; i < 64; i++) {
    for (var j = 0; j < cdata.length; j += 2) {
      var r = blowfishEncipherWords(cdata[j], cdata[j + 1], P, S);
      cdata[j] = r[0]; cdata[j + 1] = r[1];
    }
  }
  var out = new Uint8Array(cdata.length * 4);
  for (var i = 0, k = 0; i < cdata.length; i++) {
    out[k++] = (cdata[i] >>> 24) & 0xff;
    out[k++] = (cdata[i] >>> 16) & 0xff;
    out[k++] = (cdata[i] >>> 8) & 0xff;
    out[k++] = cdata[i] & 0xff;
  }
  return out;
}
/* bcrypt 只输出 24 字节，密钥更长时用 HKDF-Expand(SHA-256) 扩展（标准组合方式） */
function bcryptDerive(password, saltBytes, cost, keyLen) {
  var raw = bcryptRaw(password, saltBytes, cost);
  if (keyLen <= 24) return raw.subarray(0, keyLen);
  return hkdfSha256(raw, new Uint8Array(0), strToBytes('bcrypt-kdf'), keyLen);
}

/* ============================================================
 * 统一安全审计：扫描「当前所有选择」并给出分级提示
 *
 * 输入 cfg：{ algoId, isSym, blockSize, mode, pad, padStrict,
 *             kdfMode, kdfIter, kdfHash, nonceGuard, container,
 *             tagLen, password, fmt }
 * 输出：[{ level:'danger'|'warn'|'info', title, why, use }]
 *
 * 设计原则：只提示、不阻止——解密历史数据仍然需要这些弱算法。
 * ============================================================ */
var WEAK_HASH_RULES = [
  { test: /^(md4|md5)$/, why: '已被完全攻破：可在数秒内构造碰撞（MD5）甚至原像（MD4），不能用于任何安全场景。', use: '改用 SHA-256 / SHA-3 / BLAKE2b。' },
  { test: /^sha-?1$/, why: 'SHAttered 与 SHA-1 选前缀碰撞攻击已证实可行，证书与签名场景已被全面淘汰。', use: '改用 SHA-256 或以上。' },
  { test: /^ripemd-?160$/, why: '160 位输出，碰撞强度仅约 80 位，且缺乏现代的广泛使用与审计。', use: '改用 SHA-256。' }
];
var WEAK_ASYM_RULES = [
  { test: /^(rsa1024|rsa-?1024)/, why: '1024 位 RSA 的分解难度已接近可攻破边缘，学术界公认不安全。', use: '至少 2048 位，推荐 3072 位或改用 ECC / SM2。' },
  { test: /^(dsa|dh|elgamal)/, why: '经典有限域离散对数体系：1024 位参数已不安全，且参数生成若不规范可能存在后门。', use: '改用 ECC（P-256 起）或 SM2。' },
  { test: /^(rsa2048)/, why: '2048 位 RSA 目前仍可接受，但长期（2030 年后）不建议，且抗量子能力为零。', use: '新系统建议 3072 位或 ECC / SM2。' }
];
/* 64 位块：Sweet32 生日攻击（同一密钥加密约 2^32 个块后开始泄露明文关系） */
var SMALL_BLOCK_RULES = ['des', '3des', 'rc5', 'blowfish', 'idea', 'tea', 'xtea', 'magma'];
var UNAUTH_MODES = ['CBC', 'CFB', 'OFB', 'CTR', 'PCBC', 'CTS-CS1', 'CTS-CS2', 'CTS-CS3', 'CFB8', 'CFB1', 'XTS', 'LRW'];

function securityAudit(cfg) {
  cfg = cfg || {};
  var out = [];
  var id = cfg.algoId || '';
  var mode = cfg.mode || '';
  var push = function (level, title, why, use) { out.push({ level: level, title: title, why: why, use: use }); };

  if (mode === 'ECB') {
    push('danger', 'ECB 模式不安全', ECB_WARNING, '改用 CBC（随机 IV）或 AEAD（GCM / CCM / OCB / EAX / SIV）。');
  }
  if (mode === 'PCBC') {
    push('warn', 'PCBC 已不推荐',
      '错误传播特性使其可被构造篡改攻击（Knudsen, 1994），实践中已被 CBC 取代。',
      '改用 CBC 或 AEAD 模式。');
  }
  if (mode === 'AES-KW') {
    push('warn', 'AES-KW 只用于包装密钥',
      'RFC 3394 的密钥包装算法设计目标是保护密钥材料，不是通用数据加密；明文必须 ≥16 字节且为 8 的倍数。',
      '加密普通数据请用 GCM / CBC。');
  }
  if (UNAUTH_MODES.indexOf(mode) >= 0) {
    push('warn', mode + ' 不提供完整性保护',
      '该模式只保证机密性：攻击者翻转密文比特会造成明文相应变化，解密方无法察觉。这也是 Padding Oracle 攻击得以成立的前提。',
      '需要防篡改时改用 AEAD（GCM / CCM / OCB / EAX / SIV），或在密文后附加 HMAC。');
  }
  if (mode === 'SIV') {
    push('info', 'SIV 抗 nonce 误用',
      'SIV 是确定性认证加密：即使重复使用同一 nonce，也只会泄露「两段明文是否相同」，不会像 GCM 那样泄露明文异或。代价是加密必须两遍、且密文与明文等长。',
      '适合「无法安全保存 nonce」的场景；其它情况 GCM 更常用。');
  }
  if (mode === 'XTS' || mode === 'LRW') {
    push('info', mode + ' 面向磁盘加密',
      '它是窄块（16 字节）的可调分组密码，设计目标是原地加密固定大小的扇区，且 tweak 通常与扇区号绑定。',
      '不要把它当通用加密用；同一密钥 + 同一 tweak 绝不能加密两份不同数据。');
  }

  var wa = weakAlgoWarnings(id);
  for (var i = 0; i < wa.length; i++) push('danger', '算法强度不足', wa[i].why, wa[i].use);
  for (var i = 0; i < WEAK_HASH_RULES.length; i++) {
    if (WEAK_HASH_RULES[i].test.test(id)) push('danger', '哈希算法不安全', WEAK_HASH_RULES[i].why, WEAK_HASH_RULES[i].use);
  }
  for (var i = 0; i < WEAK_ASYM_RULES.length; i++) {
    if (WEAK_ASYM_RULES[i].test.test(id)) push('warn', '非对称参数偏弱', WEAK_ASYM_RULES[i].why, WEAK_ASYM_RULES[i].use);
  }
  if (cfg.isSym && SMALL_BLOCK_RULES.indexOf(id) >= 0 &&
      (mode === 'CBC' || mode === 'CTR' || mode === 'CFB' || mode === 'OFB')) {
    push('warn', '64 位块存在 Sweet32 风险',
      id.toUpperCase() + ' 的块只有 8 字节：同一密钥加密约 2^32 个块（约 32 GB）后，生日攻击可开始泄露明文块之间的关系。',
      '改用 AES / Camellia / SM4 等 128 位块算法，或限制单密钥加密的数据量。');
  }
  if (id === 'gg20') {
    push('danger', 'GG20 存在已知攻击面（Alpha-Rays）',
      '2023 年披露的 Alpha-Rays 攻击针对 GG18/GG20 一类 ECDSA 阈值协议的实现缺陷，多家主流库受影响。此外本实现只包含协议的算术核心（Paillier + MtA），未实现原论文中的范围证明、MtA 正确性与一致性零知识证明，因此无法抵御恶意参与者的偏离行为。',
      '真实资产请使用 FROST（RFC 9591）：它是 IETF 标准、结构更简单、且已内建对恶意行为的防护。本条目仅供协议学习与演示。');
  }
  if (id === 'frost') {
    push('info', 'FROST 的协作前提',
      '阈值签名要求 t 个参与者各自用【自己的份额】参与两轮交互；任何单一方都不掌握完整私钥。本工具为单机演示，所有份额在同一页面内使用，不具备真实多方部署的隔离性。',
      '生产环境请让各参与方在各自设备上独立运行协议，仅交换承诺与签名份额。');
  }
  if (id === 'elgamal' || /^elgamal/.test(id)) {
    push('info', 'ElGamal 密文会膨胀',
      '每个明文块产生两个密文块，加上分帧开销，最终密文约为明文的 256 倍。',
      '只用来加密会话密钥，数据本体用对称加密（混合加密）。');
  }

  if (cfg.pad === 'Zero' || cfg.pad === 'zero') {
    push('warn', '零填充有歧义',
      '解密时无法区分「补的零」和「明文自带的零」：明文末尾若本来就是 0x00，会被当作填充一并剥掉。',
      '改用 PKCS7（唯一无歧义的通用填充）。');
  }
  if (cfg.pad === 'None' || cfg.pad === 'none') {
    push('warn', '未启用填充',
      '无填充时明文长度必须是块大小的整数倍，否则会被截断或直接报错。',
      '改用 PKCS7，或在流模式 / AEAD 下自然无需填充。');
  }
  if (cfg.padStrict === 'loose') {
    push('danger', '宽松填充校验构成攻击面',
      '宽松模式下填充不合规也不报错，这正是 Padding Oracle 攻击所依赖的「可区分的失败信号」。攻击者可借此逐字节还原明文。',
      '务必切回「严格」。解密来路不明的旧数据时才临时放宽。');
  }

  if (cfg.kdfMode === 'legacy') {
    push('danger', '旧版口令派生极不安全',
      '仅对口令做一次 SHA-256 再循环填充：单次哈希没有成本放大，GPU 上每秒可试数十亿个口令。',
      '改用 Argon2id 或 PBKDF2（≥210000 次）。此档位仅用于解开历史密文。');
  }
  if (cfg.kdfMode === 'kdf2' && typeof cfg.kdfIter !== 'undefined' && cfg.kdfIter !== '' &&
      parseInt(cfg.kdfIter, 10) < 10000) {
    push('warn', 'PBKDF2 迭代次数过低',
      '当前 ' + cfg.kdfIter + ' 次，远低于 OWASP 建议的 210000，抗暴力破解能力很弱。',
      '调到 210000 以上；或改用 Argon2id。');
  }
  if (cfg.kdfMode === 'kdf2' && cfg.kdfHash === 'SHA-1') {
    push('warn', '用 SHA-1 做口令派生',
      'SHA-1 已可构造碰撞，虽对 PBKDF2 的直接影响小于签名场景，但不应出现在新系统里。',
      '改用 SHA-256 或以上。');
  }
  if (cfg.kdfMode === 'bcrypt') {
    push('info', 'bcrypt 会截断长口令',
      'bcrypt 只取口令前 72 字节，超出部分被静默丢弃——口令很长时实际参与派生的并不是全部字符。',
      '口令控制在 72 字节内，或先做一次 HKDF 压缩再交给 bcrypt。');
  }
  if (cfg.kdfMode === 'scrypt' || /^argon2/.test(cfg.kdfMode || '')) {
    push('info', '内存硬派生的参数取舍',
      (cfg.kdfMode === 'scrypt' ? 'scrypt' : cfg.kdfMode) + ' 的抗 ASIC/GPU 能力来自内存占用；参数过低退化为普通慢哈希。',
      '在可接受的延迟内尽量调高内存与轮数（本工具为交互流畅做了保守默认）。');
  }

  /* ---- 5. nonce / 标签 ---- */
  if ((cfg.nonceGuard === 'off') && ['GCM', 'CCM', 'EAX', 'OCB'].indexOf(mode) >= 0) {
    push('danger', 'nonce 复用检测已关闭',
      '同一密钥 + 同一 nonce 在 CTR 系 AEAD 下会复用密钥流：不仅泄露两段明文的异或，还能反推出认证密钥 H 从而伪造标签。',
      '保持「严格」档位，或确保每次加密都更换 nonce。');
  }
  if (['GCM', 'CCM', 'EAX', 'OCB'].indexOf(mode) >= 0 && typeof cfg.tagLen !== 'undefined' &&
      cfg.tagLen !== '' && parseInt(cfg.tagLen, 10) < 12) {
    push('warn', '认证标签过短',
      '当前 ' + cfg.tagLen + ' 字节：伪造成功率约 2^-' + (cfg.tagLen * 8) + '，对高价值数据不够。',
      '使用 16 字节（128 位）标签；空间极受限时也不建议低于 12 字节。');
  }

  if (cfg.container === 'cryptojs') {
    push('warn', 'CryptoJS 兼容格式用 MD5 派生',
      '该格式为兼容 CryptoJS 默认的 OpenSSL EVP_BytesToKey(MD5, 1 次迭代)，派生强度很低。',
      '仅在与旧 CryptoJS 系统互通时使用；新数据用 OpenSSL 容器或直接不选容器。');
  }
  if (cfg.container === 'openssl') {
    push('info', 'OpenSSL 容器的派生强度',
      'openssl enc 默认用 EVP_BytesToKey(SHA-256, 1 次迭代)，迭代次数只有 1，抗暴力破解远弱于 PBKDF2。',
      '仅在与 openssl 命令行互通时使用。');
  }

  if (cfg.fmt === 'pem') {
    push('info', 'PEM 风格只是外观',
      '这个输出只是把字节按 PEM 的折行与头尾标记排版，并不含算法标识、参数或校验，不能当真正的 PEM 证书/密钥使用。',
      '需要标准密钥文件请用「密钥导出」功能生成的 PEM。');
  }
  return out;
}

/* 兼容旧调用：securityWarnings(algoId, mode) → [{title, why, use}] */
function securityWarnings(algoId, mode) {
  return securityAudit({ algoId: algoId, mode: mode }).map(function (w) {
    return { title: w.title, why: w.why, use: w.use, level: w.level };
  });
}
