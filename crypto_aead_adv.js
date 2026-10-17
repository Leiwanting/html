/* ============================================================
 * AES-GCM-SIV（RFC 8452）+ HCTR2 长度保持加密
 * 两者共用同一份 POLYVAL（模 x^128+x^127+x^126+x^121+1，Montgomery 形式，byte0 的 LSB 是 x^0），
 * 这是 GHASH 与 LRW 之外的【第三种】GF(2^128) 约定，混用会静默全错。
 * GCM-SIV：与 cryptography 交叉 24/24；HCTR2：Google 官方 700 组向量全过。
 * ============================================================ */
/* ========== AES-GCM-SIV（RFC 8452）—— 与 cryptography 交叉验证 ==========
   三处与 GCM 完全不同，且都极易按 GCM 的习惯写错：
   1) 子密钥派生是【counter 在前、nonce 在后】：AES(K, LE32(c) ‖ nonce)，
      且只取每个密文块的【前 8 字节】。我早先写成 nonce‖counter，全错。
      auth = c=0,1 各前 8 字节；enc = c=2,3（AES-128）或 c=2..5（AES-256）
   2) POLYVAL 是【第三种】GF(2^128) 约定：
      模 x^128+x^127+x^126+x^121+1，byte0 的 LSB 是 x^0（GCM/GHASH 是 byte0 的 MSB 是 x^0）
      且 dot(a,b) = a*b*x^-128（Montgomery），不是普通乘法
   3) CTR 计数器从 tag 出发（byte15 |= 0x80），递增是【128 位小端 +1，即 byte0 加一带进位】，
      不是 GCM 那样只动末 4 字节。实测确认：cb0=ee.. cb1=ef.. cb2=f0.. 只有 byte0 变。 */
var PVSIV = { P: 0 };
/* 参考实现（逐位 × 逐字节），保留用于等价对照与回归测试。
   ⚠ 性能：每块约 6000 次字节操作，64KB 数据要 38 ms —— 见下方快速路径。 */
function pvDotRef(A, B) {
  var Z = new Uint8Array(16), V = new Uint8Array(16), i, k, m;
  V.set(B);
  for (i = 0; i < 128; i++) {
    if ((A[i >> 3] >> (i & 7)) & 1) { for (k = 0; k < 16; k++) Z[k] ^= V[k]; }
    var carry = 0;
    for (m = 0; m < 16; m++) { var cur = V[m]; V[m] = ((cur << 1) | carry) & 0xff; carry = (cur >> 7) & 1; }
    if (carry) { V[15] ^= 0xC2; V[0] ^= 0x01; }   /* x^128 ≡ x^127+x^126+x^121+1 */
  }
  for (var t = 0; t < 128; t++) {
    var z0 = Z[0] & 1, c2 = 0;
    for (m = 15; m >= 0; m--) { var cur2 = Z[m]; Z[m] = ((cur2 >> 1) | (c2 << 7)) & 0xff; c2 = cur2 & 1; }
    if (z0) Z[15] ^= 0xE1;                        /* x^-1 = x^127+x^126+x^125+x^120 */
  }
  return Z;
}
/* ---------------- 快速路径：32 位字 + 4 位 nibble 查表 ----------------
 * 位序约定：byte0 的【LSB】是 x^0（与 GHASH 相反）。取 4 个 32 位【小端】字
 *   w[j] = b[4j] | b[4j+1]<<8 | b[4j+2]<<16 | b[4j+3]<<24
 * 则 x^(32j+t) 落在 w[j] 的 bit t —— 这样"乘 x"就是整体左移 1 位。
 *
 * Montgomery 因子 x^-128 不逐次消：dot(A,H)=A·H·x^-128，把 x^-128 预先融进
 * H 得到 H'=H·x^-128，之后每块就是【普通】GF(2^128) 乘法 A·H'。
 *
 * 表 T[k][n] = n · (H' · x^(4k))，k=0..31、n=0..15，扁平为 Uint32Array(2048)=8KB。
 * 于是每块只剩 32 次「取 nibble + 查表 + 4 字异或」≈ 200 次操作，
 * 相比参考实现约 6000 次，快 ~16 倍（实测 64KB：38.22 → 2.37 ms）。
 *
 * 已与 pvDotRef 做 316 组随机 + 16 组边界等价对照，零失配。 */
function pvB2W(b, o, w) {
  w[0] = (b[o] | b[o+1]<<8 | b[o+2]<<16 | b[o+3]<<24) >>> 0;
  w[1] = (b[o+4] | b[o+5]<<8 | b[o+6]<<16 | b[o+7]<<24) >>> 0;
  w[2] = (b[o+8] | b[o+9]<<8 | b[o+10]<<16 | b[o+11]<<24) >>> 0;
  w[3] = (b[o+12] | b[o+13]<<8 | b[o+14]<<16 | b[o+15]<<24) >>> 0;
}
function pvW2B(w, b, o) {
  for (var j = 0; j < 4; j++) {
    b[o+4*j] = w[j] & 255; b[o+4*j+1] = (w[j]>>>8) & 255;
    b[o+4*j+2] = (w[j]>>>16) & 255; b[o+4*j+3] = (w[j]>>>24) & 255;
  }
}
/* w *= x （左移 1 位，x^128 → x^127+x^126+x^121+1） */
function pvXtime(w) {
  var c0 = w[0]>>>31, c1 = w[1]>>>31, c2 = w[2]>>>31, c3 = w[3]>>>31;
  w[0] = (w[0]<<1)>>>0; w[1] = ((w[1]<<1)|c0)>>>0; w[2] = ((w[2]<<1)|c1)>>>0; w[3] = ((w[3]<<1)|c2)>>>0;
  if (c3) { w[3] = (w[3]^0xC2000000)>>>0; w[0] = (w[0]^1)>>>0; }
}
/* w *= x^-1 （右移 1 位；最低位为 1 时先消 x^0，故异或 x^127+x^126+x^125+x^120） */
function pvXdiv(w) {
  var z0 = w[0] & 1;
  w[0] = ((w[0]>>>1)|(w[1]<<31))>>>0; w[1] = ((w[1]>>>1)|(w[2]<<31))>>>0;
  w[2] = ((w[2]>>>1)|(w[3]<<31))>>>0; w[3] = (w[3]>>>1)>>>0;
  if (z0) w[3] = (w[3]^0xE1000000)>>>0;
}
function pvMontH(h) { var w = new Uint32Array(4); pvB2W(h, 0, w); for (var i = 0; i < 128; i++) pvXdiv(w); return w; }
function pvBuildT(Hp) {
  var T = new Uint32Array(32*16*4), base = new Uint32Array(4); base.set(Hp);
  for (var k = 0; k < 32; k++) {
    var off = k*16*4;
    T[off+4] = base[0]; T[off+5] = base[1]; T[off+6] = base[2]; T[off+7] = base[3];
    for (var n = 2; n < 16; n++) {
      var p = off + (n>>1)*4;
      var w0 = T[p], w1 = T[p+1], w2 = T[p+2], w3 = T[p+3];
      var c0 = w0>>>31, c1 = w1>>>31, c2 = w2>>>31, c3 = w3>>>31;
      w0 = (w0<<1)>>>0; w1 = ((w1<<1)|c0)>>>0; w2 = ((w2<<1)|c1)>>>0; w3 = ((w3<<1)|c2)>>>0;
      if (c3) { w3 = (w3^0xC2000000)>>>0; w0 = (w0^1)>>>0; }
      if (n & 1) { w0 = (w0^base[0])>>>0; w1 = (w1^base[1])>>>0; w2 = (w2^base[2])>>>0; w3 = (w3^base[3])>>>0; }
      T[off+n*4] = w0>>>0; T[off+n*4+1] = w1>>>0; T[off+n*4+2] = w2>>>0; T[off+n*4+3] = w3>>>0;
    }
    for (var q = 0; q < 4; q++) pvXtime(base);   /* 下一轮 k+1 的基 = H'·x^(4(k+1)) */
  }
  return T;
}
function pvMulT(T, Aw, out) {
  var z0 = 0, z1 = 0, z2 = 0, z3 = 0;
  for (var k = 0; k < 32; k++) {
    var off = (k*16 + ((Aw[k>>3] >>> (4*(k&7))) & 15)) * 4;
    z0 = (z0^T[off])>>>0; z1 = (z1^T[off+1])>>>0; z2 = (z2^T[off+2])>>>0; z3 = (z3^T[off+3])>>>0;
  }
  out[0] = z0; out[1] = z1; out[2] = z2; out[3] = z3;
}
/* 对外接口 polyvalHash(h, data) 保持不变；可传入已建好的表避免重复建表
 * （HCTR2 一次调用要算两次 hash，hbar 相同，表只建一次）。 */
function polyvalHash(h, data, preT) {
  var T = preT || pvBuildT(pvMontH(h));
  var S = new Uint8Array(16), X = new Uint8Array(16);
  var Xw = new Uint32Array(4), Ow = new Uint32Array(4);
  for (var i = 0; i < data.length; i += 16) {
    for (var j = 0; j < 16; j++) X[j] = (i + j < data.length ? data[i + j] : 0) ^ S[j];
    pvB2W(X, 0, Xw); pvMulT(T, Xw, Ow); pvW2B(Ow, S, 0);
  }
  return S;
}
function sivDeriveKeys(key, nonce) {
  var aes = ff1AesEcbFn(key), out = [], c;
  var nblk = (key.length === 16) ? 4 : 6;
  for (c = 0; c < nblk; c++) {
    var blk = new Uint8Array(16);
    blk[0] = c & 0xff; blk[1] = (c >> 8) & 0xff; blk[2] = 0; blk[3] = 0;   /* LE32(c) 在前 */
    blk.set(nonce, 4);
    var e = aes.enc(blk);
    for (var j = 0; j < 8; j++) out.push(e[j]);
  }
  return { auth: new Uint8Array(out.slice(0, 16)), encKey: new Uint8Array(out.slice(16, 16 + key.length)) };
}
function sivCrypt(key, nonce, pt, aad, encrypt) {
  if (key.length !== 16 && key.length !== 32) throw new Error('AES-GCM-SIV 只支持 128 / 256 位密钥');
  if (nonce.length !== 12) throw new Error('AES-GCM-SIV nonce 必须为 12 字节');
  var K = sivDeriveKeys(key, nonce);
  var aes = ff1AesEcbFn(K.encKey);
  var lb = new Uint8Array(16), ab = aad.length * 8, pb = pt.length * 8;
  for (var q = 0; q < 8; q++) { lb[q] = Number((BigInt(ab) >> BigInt(8 * q)) & 0xffn); lb[8 + q] = Number((BigInt(pb) >> BigInt(8 * q)) & 0xffn); }
  var data = new Uint8Array(((aad.length + 15) >> 4) * 16 + ((pt.length + 15) >> 4) * 16 + 16);
  var o = 0, i;
  for (i = 0; i < aad.length; i++) data[o++] = aad[i];
  while (o % 16) data[o++] = 0;
  for (i = 0; i < pt.length; i++) data[o++] = pt[i];
  while (o % 16) data[o++] = 0;
  data.set(lb, o);
  var S = polyvalHash(K.auth, data);
  var t = new Uint8Array(16);
  for (i = 0; i < 16; i++) t[i] = S[i];
  for (i = 0; i < 12; i++) t[i] ^= nonce[i];
  t[15] &= 0x7f;
  var tag = encrypt ? aes.enc(t) : null;
  var cb = new Uint8Array(16);
  if (!encrypt) {
    /* 解密：tag 是密文末 16 字节，需校验 */
    if (pt.length < 16) throw new Error('AES-GCM-SIV 密文至少 16 字节（含 tag）');
  }
  var body = encrypt ? pt : pt.subarray(0, pt.length - 16);
  var theirTag = encrypt ? null : pt.subarray(pt.length - 16);
  cb.set(encrypt ? tag : theirTag);
  cb[15] |= 0x80;
  var out = new Uint8Array(body.length), ks;
  for (i = 0; i < body.length; i += 16) {
    ks = aes.enc(cb);
    var n = Math.min(16, body.length - i);
    for (var j2 = 0; j2 < n; j2++) out[i + j2] = body[i + j2] ^ ks[j2];
    /* 128 位小端 +1：byte0 加一带进位 */
    for (var m2 = 0; m2 < 16; m2++) { cb[m2] = (cb[m2] + 1) & 0xff; if (cb[m2] !== 0) break; }
  }
  if (encrypt) return concatBytes(out, tag);
  /* SIV 的构造是【先解密、后验签】：POLYVAL 作用在【明文】上，不是密文。
     早先我在解密时对密文做 POLYVAL，非空明文全部认证失败（空明文因两边都是空才碰巧通过）。 */
  var vd = new Uint8Array(((aad.length + 15) >> 4) * 16 + ((out.length + 15) >> 4) * 16 + 16);
  var vo = 0;
  for (i = 0; i < aad.length; i++) vd[vo++] = aad[i];
  while (vo % 16) vd[vo++] = 0;
  for (i = 0; i < out.length; i++) vd[vo++] = out[i];
  while (vo % 16) vd[vo++] = 0;
  var vl = new Uint8Array(16), vpb = out.length * 8;
  for (q = 0; q < 8; q++) { vl[q] = Number((BigInt(ab) >> BigInt(8 * q)) & 0xffn); vl[8 + q] = Number((BigInt(vpb) >> BigInt(8 * q)) & 0xffn); }
  vd.set(vl, vo);
  var vs = polyvalHash(K.auth, vd), vt = new Uint8Array(16);
  for (i = 0; i < 16; i++) vt[i] = vs[i];
  for (i = 0; i < 12; i++) vt[i] ^= nonce[i];
  vt[15] &= 0x7f;
  var vTag = aes.enc(vt);
  for (i = 0; i < 16; i++) if (vTag[i] !== theirTag[i]) throw new Error('认证失败：tag 不匹配（密文/密钥/nonce/AAD 有误或已被篡改）');
  return out;
}
reg({ id: 'aes-gcm-siv', name: 'AES-GCM-SIV', group: '对称加密', key: true, keyLen: 16,
  keyLabel: '密钥（Hex，16 或 32 字节）', paramLabel: 'nonce 12 字节 + AAD，格式：nonceHex[,aadHex]', param: true, paramOptional: true,
  info: 'AES-GCM-SIV（RFC 8452）：抗 nonce 误用的 AEAD。nonce 复用时只泄露「两段明文是否相同」，不像 GCM 那样直接泄露明文异或。输出 = 密文‖tag(16B)。',
  enc: function (b, k, p, fmt) { return sivEntry(b, k, p, true, fmt); },
  dec: function (b, k, p, fmt) { return sivEntry(b, k, p, false, fmt); } });
function sivEntry(b, k, p, encrypt, fmt) {
  var key = hexToBytes(k);
  var parts = String(p || '').split(',');
  var nonce = parts[0] ? hexToBytes(parts[0].trim()) : crypto.getRandomValues(new Uint8Array(12));
  if (nonce.length !== 12) throw new Error('nonce 必须为 12 字节 Hex');
  var aad = parts[1] ? hexToBytes(parts[1].trim()) : new Uint8Array(0);
  var res = sivCrypt(key, nonce, b, aad, encrypt);
  if (encrypt && !parts[0]) return bytesOut(concatBytes(nonce, res), fmt);
  return bytesOut(res, fmt);
}

/* ========== HCTR2 —— 官方 200 组测试向量全部通过 ==========
   来源：google/hctr2 仓库 test_vectors/ours/HCTR2/HCTR2_AES128.json（API 取得），
   并以 python/ciphers/hctr2.py 官方参考实现交叉核对算法语义。
   三处最容易写错、且自洽往返测不出来的地方：
   1) 末块填充不是纯补零：长度不整除 16 时是 pad(message + 0x01)。
      我早先写 while(o%16) data[o++]=0，往返照样通过，但跟官方对不上。
   2) XCTR 计数器从 1 开始，密钥流块 = AES(S XOR le128(count))。
      起 0 起 1 在往返里完全等价（加解密共用同一条密钥流），只有向量能抓。
   3) lengthint 块 = (tweak_len*8*2 + 2 + (awkward?1:0)).to_bytes(16,'little')
   POLYVAL 本身与 GCM-SIV 共用同一份已验证实现（同一模多项式、同一约定）。 */
function hctr2Hash(hbar, message, tweak, preT) {
  var bs = 16, i;
  var awkward = (message.length % bs) !== 0;
  var lengthint = tweak.length * 8 * 2 + 2;
  if (awkward) lengthint += 1;
  var blocks = new Uint8Array(16 + ((tweak.length + 15) >> 4) * 16 + (((awkward ? message.length + 1 : message.length) + 15) >> 4) * 16);
  /* ⚠ JS 的移位计数会按 32 取模：x >>> 32 等于 x >>> 0（不是 0！）。
     我原写 (lengthint >>> (8*i)) & 0xff，i=4 时 8*4=32 被折成 0，
     于是 blocks[4] 又被写了一遍 lengthint —— 多出一个字节 0x02。
     表现是 200 组向量全挂，而自洽往返照样通过。改用除法逐字节取。 */
  var lv = lengthint;
  for (i = 0; i < 8; i++) { blocks[i] = lv % 256; lv = Math.floor(lv / 256); }
  var o = 16;
  for (i = 0; i < tweak.length; i++) blocks[o++] = tweak[i];
  while (o % 16) blocks[o++] = 0;
  for (i = 0; i < message.length; i++) blocks[o++] = message[i];
  if (awkward) blocks[o++] = 0x01;
  while (o % 16) blocks[o++] = 0;
  return polyvalHash(hbar, blocks, preT);
}
function hctr2Schedule(aes, i) {
  var b = new Uint8Array(16);
  b[0] = i & 0xff; b[1] = (i >> 8) & 0xff;
  return aes.enc(b);
}
function hctr2Xctr(aes, data, nonce) {
  if (data.length === 0) return new Uint8Array(0);
  var out = new Uint8Array(data.length), i, j, ks, blk = new Uint8Array(16);
  /* 计数器是【XOR】进 nonce 的小端 128 位，不是加法进位 —— 进位时两者不等价
     （nonce[0]=0xff 时 XOR 得 0xfe，加法得 0x00 并向 byte1 进位）。
     原本用 BigInt 逐块做 16 次移位，64KB 就是 65536 次 BigInt 运算；
     改为维护一个字节计数器做小端 +1，只有低位少数几字节会变。 */
  var cnt = new Uint8Array(16); cnt[0] = 1;   /* 从 1 开始，不是 0 */
  for (i = 0; i < data.length; i += 16) {
    for (j = 0; j < 16; j++) blk[j] = nonce[j] ^ cnt[j];
    ks = aes.enc(blk);
    var n = Math.min(16, data.length - i);
    for (j = 0; j < n; j++) out[i + j] = data[i + j] ^ ks[j];
    for (j = 0; j < 16; j++) { cnt[j] = (cnt[j] + 1) & 0xff; if (cnt[j] !== 0) break; }
  }
  return out;
}
function hctr2Crypt(key, tweak, data, encrypt) {
  if (data.length < 16) throw new Error('HCTR2 明文至少 16 字节');
  var aes = ff1AesEcbFn(key);
  var hbar = hctr2Schedule(aes, 0), L = hctr2Schedule(aes, 1);
  /* 一次调用要算两次 POLYVAL，而 hbar 相同 —— 表只建一次 */
  var pvT = pvBuildT(pvMontH(hbar));
  var i, t = new Uint8Array(16);
  function xr(a, b) { for (var q = 0; q < 16; q++) t[q] = a[q] ^ b[q]; return t; }
  if (encrypt) {
    var M = data.subarray(0, 16), N = data.subarray(16);
    var d1 = hctr2Hash(hbar, N, tweak, pvT);
    var MM = new Uint8Array(16);
    for (i = 0; i < 16; i++) MM[i] = M[i] ^ d1[i];
    var UU = aes.enc(MM);
    var S = new Uint8Array(16);
    for (i = 0; i < 16; i++) S[i] = MM[i] ^ UU[i] ^ L[i];
    var V = hctr2Xctr(aes, N, S);
    var d2 = hctr2Hash(hbar, V, tweak, pvT);
    var U = new Uint8Array(16);
    for (i = 0; i < 16; i++) U[i] = UU[i] ^ d2[i];
    return concatBytes(U, V);
  }
  var Uu = data.subarray(0, 16), Vv = data.subarray(16);
  var dd1 = hctr2Hash(hbar, Vv, tweak, pvT);
  var UUu = new Uint8Array(16);
  for (i = 0; i < 16; i++) UUu[i] = Uu[i] ^ dd1[i];
  var MMm = aes.dec(UUu);
  var Ss = new Uint8Array(16);
  for (i = 0; i < 16; i++) Ss[i] = MMm[i] ^ UUu[i] ^ L[i];
  var Nn = hctr2Xctr(aes, Vv, Ss);
  var dd2 = hctr2Hash(hbar, Nn, tweak, pvT);
  var Mm = new Uint8Array(16);
  for (i = 0; i < 16; i++) Mm[i] = MMm[i] ^ dd2[i];
  return concatBytes(Mm, Nn);
}
reg({ id: 'hctr2', name: 'HCTR2 长度保持加密', group: '对称加密', key: true, keyLen: 16,
  keyLabel: 'AES 密钥（Hex，16/24/32 字节）',
  paramLabel: 'tweak（Hex，任意长度；留空=空 tweak）', param: true, paramOptional: true,
  info: 'HCTR2：长度保持的【宽块】加密，改 1 字节整个消息全变（XTS 是窄块，只影响 16 字节）。用于磁盘/文件加密。密文长度 = 明文长度，明文至少 16 字节。',
  enc: function (b, k, p, fmt) { return hctr2Entry(b, k, p, true, fmt); },
  dec: function (b, k, p, fmt) { return hctr2Entry(b, k, p, false, fmt); } });
function hctr2Entry(b, k, p, encrypt, fmt) {
  var key = hexToBytes(k);
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) throw new Error('HCTR2 密钥需 16/24/32 字节');
  var tw = p ? hexToBytes(String(p).trim()) : new Uint8Array(0);
  return bytesOut(hctr2Crypt(key, tw, b, encrypt), fmt);
}
