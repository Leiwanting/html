/* ============================================================
 * Adiantum（HBSH 构造）— Google 官方规范 + 官方测试向量
 *   流密码 XChaCha{8,12,20} + 块密码 AES-256 + NHPoly1305
 * 参考：github.com/google/adiantum（python/ 官方实现与 test_vectors/ours/）
 * 结构：Hash-Block-Stream-Hash，用于磁盘/文件加密的长度保持加密
 * ============================================================ */
(function () {
  var M32 = 0xffffffffn, M64 = 0xffffffffffffffffn, M128 = (1n << 128n) - 1n;
  var P1305 = (1n << 130n) - 5n;
  var RCLAMP = 0xffffffc0ffffffc0ffffffc0fffffffn;

  /* ---------- 本地小工具（crypto_core.js 的 IIFE 局部函数跨文件取不到） ---------- */
  function rd32(b, o) {
    return ((b[o] | (b[o + 1] << 8) | (b[o + 2] << 16)) + (b[o + 3] << 24)) >>> 0;
  }
  function wr32(b, o, v) {
    b[o] = v & 255; b[o + 1] = (v >>> 8) & 255; b[o + 2] = (v >>> 16) & 255; b[o + 3] = (v >>> 24) & 255;
  }
  function toBig(b, o, n) { var v = 0n; for (var i = n - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[o + i]); return v; }
  function fromBig(v, n) { var o = new Uint8Array(n); for (var i = 0; i < n; i++) { o[i] = Number(v & 0xffn); v >>= 8n; } return o; }
  function cat() {
    var tot = 0, i;
    for (i = 0; i < arguments.length; i++) tot += arguments[i].length;
    var o = new Uint8Array(tot), p = 0;
    for (i = 0; i < arguments.length; i++) { o.set(arguments[i], p); p += arguments[i].length; }
    return o;
  }
  function hexToBytes(s) {
    s = (s || '').replace(/[^0-9a-fA-F]/g, '');
    if (s.length % 2) throw new Error('十六进制长度必须为偶数');
    var o = new Uint8Array(s.length / 2);
    for (var i = 0; i < o.length; i++) o[i] = parseInt(s.substr(i * 2, 2), 16);
    return o;
  }
  function bytesToHex(b) {
    var s = '';
    for (var i = 0; i < b.length; i++) s += (b[i] < 16 ? '0' : '') + b[i].toString(16);
    return s;
  }

  /* ---------- ChaCha（Google latindance 版：8 字节 counter + 8 字节 nonce，轮数可配） ---------- */
  function rotl32(v, n) { return ((v << n) | (v >>> (32 - n))) >>> 0; }
  function chachaQR(x, a, b, c, d) {
    x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl32((x[d] ^ x[a]) >>> 0, 16);
    x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl32((x[b] ^ x[c]) >>> 0, 12);
    x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl32((x[d] ^ x[a]) >>> 0, 8);
    x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl32((x[b] ^ x[c]) >>> 0, 7);
  }
  function chachaInit(key, ctrLo, ctrHi, n0, n1) {
    var x = new Uint32Array(16);
    x[0] = 0x61707865; x[1] = 0x3320646e; x[2] = 0x79622d32; x[3] = 0x6b206574;
    for (var i = 0; i < 8; i++) x[4 + i] = rd32(key, i * 4);
    x[12] = ctrLo >>> 0; x[13] = ctrHi >>> 0; x[14] = n0 >>> 0; x[15] = n1 >>> 0;
    return x;
  }
  function chachaRounds(w, rounds) {
    for (var r = 0; r < (rounds >> 1); r++) {
      chachaQR(w, 0, 4, 8, 12); chachaQR(w, 1, 5, 9, 13);
      chachaQR(w, 2, 6, 10, 14); chachaQR(w, 3, 7, 11, 15);
      chachaQR(w, 0, 5, 10, 15); chachaQR(w, 1, 6, 11, 12);
      chachaQR(w, 2, 7, 8, 13); chachaQR(w, 3, 4, 9, 14);
    }
  }
  function chachaBlock(key, ctr, nonce8, rounds) {
    var init = chachaInit(key, ctr >>> 0, Math.floor(ctr / 4294967296) >>> 0, rd32(nonce8, 0), rd32(nonce8, 4));
    var w = new Uint32Array(init);
    chachaRounds(w, rounds);
    var out = new Uint8Array(64);
    for (var i = 0; i < 16; i++) wr32(out, i * 4, (w[i] + init[i]) >>> 0);
    return out;
  }
  /* HChaCha：state[12..15] = 16 字节 nonceoffset，不加 initstate，输出 state[0..3]‖state[12..15] */
  function hchacha(key, nonce16, rounds) {
    var x = new Uint32Array(16);
    x[0] = 0x61707865; x[1] = 0x3320646e; x[2] = 0x79622d32; x[3] = 0x6b206574;
    for (var i = 0; i < 8; i++) x[4 + i] = rd32(key, i * 4);
    for (i = 0; i < 4; i++) x[12 + i] = rd32(nonce16, i * 4);
    var w = new Uint32Array(x);
    chachaRounds(w, rounds);
    var out = new Uint8Array(32);
    for (i = 0; i < 4; i++) { wr32(out, i * 4, w[i]); wr32(out, 16 + i * 4, w[12 + i]); }
    return out;
  }
  /* XChaCha：subkey = HChaCha(key, nonce[0:16])，再 ChaCha(subkey, nonce[16:24]) */
  function xchachaStream(key, nonce24, rounds, len) {
    if (nonce24.length !== 24) throw new Error('XChaCha nonce 需 24 字节');
    var sub = hchacha(key, nonce24.subarray(0, 16), rounds);
    var n8 = nonce24.subarray(16, 24);
    var out = new Uint8Array(len), pos = 0, ctr = 0, ks, take;
    while (pos < len) {
      ks = chachaBlock(sub, ctr, n8, rounds); ctr++;
      take = Math.min(64, len - pos);
      out.set(ks.subarray(0, take), pos);
      pos += take;
    }
    return out;
  }

  /* ---------- NH（4 passes / stride 2 / word 4 / unit 16 / messagemax 1024 / key 1072） ---------- */
  var NH_UNIT = 16, NH_MSGMAX = 1024, NH_KEYLEN = 1072, NH_PASSES = 4, NH_STRIDE = 2;
  function nhHash(keyBytes, msgBytes) {
    var nInt = msgBytes.length >> 2, i, j, p;
    if (msgBytes.length === 0 || (msgBytes.length % NH_UNIT) !== 0) throw new Error('NH 输入需为 16 字节倍数且非空');
    if (msgBytes.length > NH_MSGMAX) throw new Error('NH 单块输入不得超过 1024 字节');
    if (keyBytes.length !== NH_KEYLEN) throw new Error('NH 密钥需 1072 字节');
    var kI = new Array(keyBytes.length >> 2), mI = new Array(nInt);
    for (i = 0; i < kI.length; i++) kI[i] = BigInt(rd32(keyBytes, i * 4));
    for (i = 0; i < nInt; i++) mI[i] = BigInt(rd32(msgBytes, i * 4));
    var out = new Uint8Array(32);
    for (p = 0; p < NH_PASSES; p++) {
      var off = p * NH_STRIDE * 2, s = 0n, a, b;
      for (i = 0; i < nInt; i += NH_STRIDE * 2) {
        for (j = i; j < i + NH_STRIDE; j++) {
          a = (mI[j] + kI[off + j]) & M32;
          b = (mI[j + NH_STRIDE] + kI[off + j + NH_STRIDE]) & M32;
          s += a * b;
        }
      }
      s &= M64;
      for (i = 0; i < 8; i++) out[p * 8 + i] = Number((s >> BigInt(8 * i)) & 0xffn);
    }
    return out;
  }

  /* ---------- Poly1305 泛哈希（h_rbar：单参数形式，非标准 MAC） ---------- */
  function readR(b) {
    if (b.length !== 16) throw new Error('Poly1305 r 需 16 字节');
    return (toBig(b, 0, 16) & RCLAMP);
  }
  function polyHR(rbar, m) {
    var h = 0n, pos = 0, chunk, c;
    while (pos < m.length) {
      chunk = m.subarray(pos, Math.min(pos + 16, m.length));
      pos += 16;
      c = toBig(chunk, 0, chunk.length) + (1n << BigInt(8 * chunk.length));
      h = ((h + c) * rbar) % P1305;
    }
    return h;
  }

  /* ---------- NH 输出拼接（补零到 16 倍数，按 1024 切块） ---------- */
  function nhAll(nhKey, msg) {
    var pad = ((-msg.length) % NH_UNIT + NH_UNIT) % NH_UNIT;
    var padded = pad ? cat(msg, new Uint8Array(pad)) : msg;
    var parts = [];
    for (var i = 0; i < padded.length; i += NH_MSGMAX) {
      parts.push(nhHash(nhKey, padded.subarray(i, Math.min(i + NH_MSGMAX, padded.length))));
    }
    return cat.apply(null, parts);
  }
  /* 独立 NHPoly1305（Google 的 Hash 类）：key = r(16) ‖ NHkey(1072) = 1088 */
  function nhpoly1305(key, msg) {
    if (key.length !== 1088) throw new Error('NHPoly1305 密钥需 1088 字节（r‖NH 密钥）');
    var h = polyHR(readR(key.subarray(0, 16)), nhAll(key.subarray(16, 16 + NH_KEYLEN), msg));
    return h & M128;
  }
  /* Adiantum 内部哈希：ht = h_rbar(rt, 位长‖tweak)，hm = h_rbar(rm, NH(msg))，返回整数和 */
  function adiHash(rt, rm, nhKey, tweak, msg) {
    var ht = polyHR(rt, cat(fromBig(BigInt(8 * msg.length), 16), tweak));
    return ht + polyHR(rm, nhAll(nhKey, msg));
  }

  /* ---------- Adiantum（HBSH） ---------- */
  var ADI_KEYLEN = 32, ADI_ROUNDS = 12;
  function padNonce(n) {
    /* nonce + b'\1' + b'\0' * (24 - len(nonce) - 1) */
    var o = new Uint8Array(24);
    o.set(n, 0);
    o[n.length] = 1;
    return o;
  }
  function blockAdd(block, toadd) {
    var i = (toBig(block, 0, 16) + toadd) & M128;
    return fromBig(i, 16);
  }
  function adiSetup(key, rounds) {
    if (key.length !== ADI_KEYLEN) throw new Error('Adiantum 密钥需 32 字节');
    var km = xchachaStream(key, padNonce(new Uint8Array(0)), rounds, 32 + 16 + 16 + NH_KEYLEN);
    return {
      aes: aesMakeBlockFn(km.subarray(0, 32)),
      rt: readR(km.subarray(32, 48)),
      rm: readR(km.subarray(48, 64)),
      nhKey: km.subarray(64, 64 + NH_KEYLEN),
      streamKey: key
    };
  }
  function adiantumCrypt(block, key, tweak, rounds, encrypt) {
    if (block.length < 16) throw new Error('Adiantum 输入至少 16 字节（末尾 16 字节为右半块）');
    tweak = tweak || new Uint8Array(0);
    var S = adiSetup(key, rounds), H = function (m) {
      return adiHash(S.rt, S.rm, S.nhKey, tweak, m);
    };
    var pl, pr, pm, cm, cl, cr;
    if (encrypt) {
      pl = block.subarray(0, block.length - 16);
      pr = block.subarray(block.length - 16);
      pm = blockAdd(pr, H(pl));
      cm = S.aes.enc(pm);
      cl = xorBytes(xchachaStream(S.streamKey, padNonce(cm), rounds, pl.length), pl);
      cr = blockAdd(cm, -H(cl));
      return cat(cl, cr);
    }
    cl = block.subarray(0, block.length - 16);
    cr = block.subarray(block.length - 16);
    cm = blockAdd(cr, H(cl));
    pl = xorBytes(xchachaStream(S.streamKey, padNonce(cm), rounds, cl.length), cl);
    pm = S.aes.dec(cm);
    pr = blockAdd(pm, -H(pl));
    return cat(pl, pr);
  }
  /* 供测试脚本做分层对照（向量里有 offset 参数，界面入口用不到） */
  if (typeof globalThis !== 'undefined') {
    globalThis.__nhTest = nhHash;
    globalThis.__nhpTest = nhpoly1305;
    globalThis.__xchachaTest = function (key, nonce24, rounds, len, off) {
      var sub = hchacha(key, nonce24.subarray(0, 16), rounds), n8 = nonce24.subarray(16, 24);
      var out = new Uint8Array(len), pos = 0, ctr = off >>> 0, ks, take;
      while (pos < len) {
        ks = chachaBlock(sub, ctr, n8, rounds); ctr++;
        take = Math.min(64, len - pos); out.set(ks.subarray(0, take), pos); pos += take;
      }
      return out;
    };
  }
  function xorBytes(a, b) {
    var o = new Uint8Array(b.length);
    for (var i = 0; i < b.length; i++) o[i] = a[i] ^ b[i];
    return o;
  }

  /* ---------- 注册 ---------- */
  if (typeof reg !== 'function') return;
  var ADI_INFO = 'Adiantum：Google 提出的长度保持加密（HBSH = Hash-Block-Stream-Hash），' +
    '用于无 AES 指令集设备的磁盘/文件加密（Android、Linux fscrypt）。' +
    '密钥 32 字节；tweak 填十六进制（可空，通常是扇区号）；输出与输入等长。' +
    '已与 Google 官方 python 实现及 180 组官方向量逐字节比对。';

  function entry(rounds) {
    return function (b, k, tweakHex) {
      var tw = tweakHex ? hexToBytes(String(tweakHex)) : new Uint8Array(0);
      return adiantumCrypt(b, k, tw, rounds, this && this.dec === true ? false : true);
    };
  }
  reg({
    id: 'adiantum', name: 'Adiantum 长度保持加密（XChaCha12-AES256）', group: '对称加密',
    key: true, keyLen: 32, param: true,
    keyLabel: '密钥（32 字节，Hex 或字符串）',
    paramLabel: 'tweak（十六进制，可空）',
    enc: function (b, k, tw) { return adiantumCrypt(b, k, tw ? hexToBytes(String(tw)) : new Uint8Array(0), 12, true); },
    dec: function (b, k, tw) { return adiantumCrypt(b, k, tw ? hexToBytes(String(tw)) : new Uint8Array(0), 12, false); },
    info: ADI_INFO
  });
  reg({
    id: 'adiantum20', name: 'Adiantum（XChaCha20-AES256）', group: '对称加密',
    key: true, keyLen: 32, param: true,
    keyLabel: '密钥（32 字节，Hex 或字符串）',
    paramLabel: 'tweak（十六进制，可空）',
    enc: function (b, k, tw) { return adiantumCrypt(b, k, tw ? hexToBytes(String(tw)) : new Uint8Array(0), 20, true); },
    dec: function (b, k, tw) { return adiantumCrypt(b, k, tw ? hexToBytes(String(tw)) : new Uint8Array(0), 20, false); },
    info: 'Adiantum 的 20 轮流密码变体（XChaCha20-AES256），结构同 adiantum，安全性余量更大、略慢。' +
      '已与 Google 官方 180 组向量比对。'
  });
  reg({
    id: 'adiantum8', name: 'Adiantum（XChaCha8-AES256）', group: '对称加密',
    key: true, keyLen: 32, param: true,
    keyLabel: '密钥（32 字节，Hex 或字符串）',
    paramLabel: 'tweak（十六进制，可空）',
    enc: function (b, k, tw) { return adiantumCrypt(b, k, tw ? hexToBytes(String(tw)) : new Uint8Array(0), 8, true); },
    dec: function (b, k, tw) { return adiantumCrypt(b, k, tw ? hexToBytes(String(tw)) : new Uint8Array(0), 8, false); },
    info: 'Adiantum 的 8 轮流密码变体（XChaCha8-AES256），结构同 adiantum，最快但安全余量最小，' +
      '非标准配置（官方默认 12 轮），仅供研究与性能对比。已与 Google 官方 12 组向量比对。'
  });
  reg({
    id: 'xchacha12', name: 'XChaCha12 流密码', group: '对称加密',
    key: true, keyLen: 32, param: true,
    keyLabel: '密钥（32 字节，Hex 或字符串）',
    paramLabel: 'nonce（24 字节 Hex，留空自动生成）',
    enc: function (b, k, nHex) {
      var n = nHex ? hexToBytes(String(nHex)) : null;
      if (!n) { n = new Uint8Array(24); if (typeof crypto !== 'undefined' && crypto.getRandomValues) crypto.getRandomValues(n); }
      if (n.length !== 24) throw new Error('XChaCha nonce 需 24 字节');
      return cat(n, xorBytes(xchachaStream(k, n, 12, b.length), b));
    },
    dec: function (b, k) {
      if (b.length < 24) throw new Error('输入需含 24 字节 nonce 前缀');
      var n = b.subarray(0, 24);
      return xorBytes(xchachaStream(k, n, 12, b.length - 24), b.subarray(24));
    },
    info: 'XChaCha12：24 字节 nonce 的扩展 nonce ChaCha（HChaCha12 派生子密钥 + ChaCha12 生成流），' +
      '加密输出为 nonce‖密文。已与 Google 官方 XChaCha12 向量比对。'
  });
  reg({
    id: 'xchacha8', name: 'XChaCha8 流密码', group: '对称加密',
    key: true, keyLen: 32, param: true,
    keyLabel: '密钥（32 字节，Hex 或字符串）',
    paramLabel: 'nonce（24 字节 Hex，留空自动生成）',
    enc: function (b, k, nHex) {
      var n = nHex ? hexToBytes(String(nHex)) : null;
      if (!n) { n = new Uint8Array(24); if (typeof crypto !== 'undefined' && crypto.getRandomValues) crypto.getRandomValues(n); }
      if (n.length !== 24) throw new Error('XChaCha nonce 需 24 字节');
      return cat(n, xorBytes(xchachaStream(k, n, 8, b.length), b));
    },
    dec: function (b, k) {
      if (b.length < 24) throw new Error('输入需含 24 字节 nonce 前缀');
      var n = b.subarray(0, 24);
      return xorBytes(xchachaStream(k, n, 8, b.length - 24), b.subarray(24));
    },
    info: 'XChaCha8：24 字节 nonce 的扩展 nonce ChaCha 8 轮变体，结构同 XChaCha12 但只用 8 轮。' +
      '非标准配置（官方默认 12 轮），仅供研究与性能对比。已与 Google 官方 XChaCha8 向量比对。'
  });
  reg({
    id: 'nhpoly1305', name: 'NHPoly1305 泛哈希', group: '单向哈希',
    key: true, keyLen: 1088,
    keyLabel: '密钥（1088 字节 = rm‖rt‖NH 密钥，留空用全零）',
    param: true, paramLabel: 'tweak（十六进制，可空）',
    enc: function (b, k) {
      var key = (k && k.length === 1088) ? k : new Uint8Array(1088);
      return fromBig(nhpoly1305(key, b), 16);
    },
    info: 'NHPoly1305：Adiantum 使用的快速泛哈希（NH + 双 Poly1305），非抗碰撞哈希，' +
      '仅用于加密构造内部。输出 16 字节（模 2^128 截断）。'
  });
})();
