/* ============================================================
 * crypto_core.js —— 算法内核（原 crypto-extra.js ~ crypto-extra5.js 合并）
 *
 * 收录：分组密码（Blowfish/IDEA/Twofish/Camellia/Serpent/Kuznyechik/GOST Magma/
 * TEA 族/AES 系）、流密码、AEAD（GCM/CCM/SIV/EAC/OCB/Poly1305）、
 * 非对称（RSA/ECC/ElGamal/DSA/SM2/DH/X25519 系）、
 * 哈希与 MAC（SHA 系/SHA3/BLAKE2/Streebog/SM3/RIPEMD/CMAC/KMAC/…）、
 * KDF（PBKDF2/scrypt/HKDF/Argon2）、古典密码。
 *
 * 依赖：Encryption_and_decryption_logic.js（提供 reg / oneway / regSym / 工具函数）
 *       crypto_tables.js（提供 S-box 等常量表）
 * ============================================================ */
'use strict';

/* ============================================================
 * crypto-extra.js
 * 依赖 Encryption_and_decryption_logic.js 中的全局：
 *   reg(), ALGOS, modeEnc, modeDec, modeNeedsIV, modeUsesPadding,
 *   bytesOut, bytesIn, deriveKeyBytes, strToBytes, bytesToStr,
 *   concatBytes, hexToBytes, bytesToHex,
 *   readU32BE, writeU32BE, rotl32, rotr32
 * 以及 window.rebuildAlgoList()
 * ============================================================ */

(function () {

  if (typeof ALGOS === 'undefined' || typeof reg !== 'function') {
    console.error('crypto-extra.js 需要在 Encryption_and_decryption_logic.js 之后加载');
    return;
  }

  /* ============================================================
   * 1. BigInt 计算 π 的十六进制小数（Chudnovsky 算法），用于生成 Blowfish 常量
   * ============================================================ */

  function bigIntSqrt(n) {
    if (n < 0n) throw new Error('sqrt of negative');
    if (n < 2n) return n;
    let x = n;
    let y = (x + 1n) / 2n;
    while (y < x) { x = y; y = (x + n / x) / 2n; }
    return x;
  }

  function bigIntPow(base, exp) {
    let r = 1n;
    let b = base;
    let e = exp;
    while (e > 0n) {
      if (e & 1n) r *= b;
      b *= b;
      e >>= 1n;
    }
    return r;
  }

  function computePiHex(digits) {
    const prec = digits * 2 + 20;
    const one = bigIntPow(10n, BigInt(prec));
    function arctanInv(x) {
      const x2 = BigInt(x) * BigInt(x);
      let term = one / BigInt(x);
      let sum = term;
      let k = 1n;
      let sign = -1n;
      while (term !== 0n) {
        term = term / x2;
        const add = term / (2n * k + 1n);
        if (add === 0n) break;
        sum += sign * add;
        sign = -sign;
        k += 1n;
      }
      return sum;
    }
    const pi = 16n * arctanInv(5) - 4n * arctanInv(239);
    const intPart = pi / one;                // 3n
    let frac = pi % one;                     // 小数部分 * 10^prec
    let hex = '';
    let f = frac;
    const needHexDigits = digits;
    for (let i = 0; i < needHexDigits; i++) {
      f *= 16n;
      const d = f / one;
      hex += '0123456789abcdef'[Number(d)];
      f = f % one;
    }
    return hex; // 十六进制小数（不含 0.）
  }

  function generateBlowfishConstants() {
    const need = 1042;
    const hex = computePiHex(need * 8 + 32); // 每个 u32 = 8 hex 位
    const P = new Uint32Array(18);
    const S = new Uint32Array(4 * 256);
    let pos = 0;
    for (let i = 0; i < 18; i++) {
      P[i] = parseInt(hex.substr(pos, 8), 16) >>> 0;
      pos += 8;
    }
    for (let i = 0; i < 4 * 256; i++) {
      S[i] = parseInt(hex.substr(pos, 8), 16) >>> 0;
      pos += 8;
    }
    return { P: P, S: S };
  }

  let BF_P = null;
  let BF_S = null;

  function initBlowfish() {
    if (BF_P && BF_S) return;
    const c = generateBlowfishConstants();
    // 标准 Blowfish 的 P 盒第一个值是 0x243f6a88
    if (c.P[0] !== 0x243f6a88) {
      throw new Error('π 常量生成异常（首个 P 值 ' + c.P[0].toString(16) + ' 应为 243f6a88）');
    }
    BF_P = c.P;
    BF_S = c.S;
  }
  globalThis.blowfishFreshConstants = function () {
    initBlowfish();
    return { P: BF_P.slice(), S: BF_S.slice() };
  };
  /* 导出标准 Blowfish 单块加密（无填充），bcrypt 的 EksBlowfish 要用它做密钥扩展 */
  globalThis.blowfishEncipherWords = function (L, R, P, S) {
    return bfCore(L >>> 0, R >>> 0, P, S, true);
  };

  /* F 函数必须使用「密钥扩展后」的 S 盒（由参数传入）；
     用未过密钥的全局 BF_S 会让 S 盒与密钥无关，结果不是标准 Blowfish */
  function bfF(x, S) {
    const a = (x >>> 24) & 0xff;
    const b = (x >>> 16) & 0xff;
    const c = (x >>> 8) & 0xff;
    const d = x & 0xff;
    return (((S[a] + S[256 + b]) >>> 0 ^ S[512 + c]) + S[768 + d]) >>> 0;
  }

  /* 标准 Blowfish 核心：16 轮 Feistel → 撤销最后一次交换 → 白化 */
  function bfCore(L, R, P, S, enc) {
    if (enc) {
      for (let i = 0; i < 16; i++) {
        L = (L ^ P[i]) >>> 0;
        R = (R ^ bfF(L, S)) >>> 0;
        const t = L; L = R; R = t;
      }
    } else {
      for (let i = 17; i > 1; i--) {
        L = (L ^ P[i]) >>> 0;
        R = (R ^ bfF(L, S)) >>> 0;
        const t = L; L = R; R = t;
      }
    }
    const u = L; L = R; R = u;   /* 撤销最后一次交换 */
    if (enc) { R = (R ^ P[16]) >>> 0; L = (L ^ P[17]) >>> 0; }
    else { R = (R ^ P[1]) >>> 0; L = (L ^ P[0]) >>> 0; }
    return [L, R];
  }

  function bfEncryptBlock(block, P, S) {
    const r = bfCore(readU32BE(block, 0), readU32BE(block, 4), P, S, true);
    const out = new Uint8Array(8);
    writeU32BE(r[0], out, 0);
    writeU32BE(r[1], out, 4);
    return out;
  }

  function bfDecryptBlock(block, P, S) {
    const r = bfCore(readU32BE(block, 0), readU32BE(block, 4), P, S, false);
    const out = new Uint8Array(8);
    writeU32BE(r[0], out, 0);
    writeU32BE(r[1], out, 4);
    return out;
  }

  function bfKeySchedule(keyBytes) {
    initBlowfish();
    const P = new Uint32Array(BF_P);
    const S = new Uint32Array(BF_S);

    let j = 0;
    for (let i = 0; i < 18; i++) {
      let v = 0;
      for (let k = 0; k < 4; k++) {
        v = ((v << 8) | keyBytes[j % keyBytes.length]) >>> 0;
        j++;
      }
      P[i] = (P[i] ^ v) >>> 0;
    }

    let L = 0, R = 0;
    /* 密钥扩展里的「加密」必须与真正的加密函数完全一致 */
    function encryptBlockInternal() {
      const r = bfCore(L, R, P, S, true);
      L = r[0]; R = r[1];
    }

    for (let i = 0; i < 18; i += 2) {
      encryptBlockInternal();
      P[i] = L; P[i + 1] = R;
    }
    for (let i = 0; i < 4; i++) {
      for (let k = 0; k < 256; k += 2) {
        encryptBlockInternal();
        S[i * 256 + k] = L;
        S[i * 256 + k + 1] = R;
      }
    }
    return { P: P, S: S };
  }

  function bfMakeBlockFn(keyBytes) {
    const kb = keyBytes;
    const { P, S } = bfKeySchedule(kb);
    return {
      enc: function (b) { return bfEncryptBlock(b, P, S); },
      dec: function (b) { return bfDecryptBlock(b, P, S); }
    };
  }

  /* ============================================================
   * 2. IDEA
   * ============================================================ */

  const IDEA_MOD = 0x10000;    /* 2^16，同时是「0」在乘法群里的替身 */
  const IDEA_MUL_MOD = 0x10001; /* 2^16 + 1（素数） */
  function ideaMul(a, b) {
    if (a === 0) a = IDEA_MOD;
    if (b === 0) b = IDEA_MOD;
    /* 用整数归约代替浮点取模：2^16 ≡ -1 (mod 2^16+1)，
     * 故 a*b ≡ (低 16 位) - (高 16 位)，且差值 ∈ [-1, 0xFFFF] 只需补一次。 */
    const p = a * b;
    const lo = p & 0xFFFF;
    const hi = (p / 0x10000) | 0;   /* p ≤ 2^32，不能写成 p >>> 16（会溢出成 0） */
    let x = lo - hi;
    if (x < 0) x += IDEA_MUL_MOD;
    return x === IDEA_MOD ? 0 : x;
  }
  function ideaMulInv(a) {
    const x = a === 0 ? IDEA_MOD : a;   /* 0 → 2^16，其逆元是它自身 */
    let t0 = 0, t1 = 1, r0 = IDEA_MUL_MOD, r1 = x;
    while (r1 !== 0) {
      const q = Math.floor(r0 / r1);
      const tr = r0 - q * r1; r0 = r1; r1 = tr;
      const tt = t0 - q * t1; t0 = t1; t1 = tt;
    }
    if (t0 < 0) t0 += IDEA_MUL_MOD;
    if (t0 < 0) t0 += IDEA_MUL_MOD;
    return t0 === IDEA_MOD ? 0 : (t0 % IDEA_MUL_MOD);
  }
  function ideaAddInv(a) { return (IDEA_MOD - a) & 0xFFFF; }

  function ideaExpandKey(keyBytes) {
    const K = new Uint16Array(52);
    for (let i = 0; i < 8; i++) K[i] = ((keyBytes[i * 2] << 8) | keyBytes[i * 2 + 1]) & 0xFFFF;
    for (let idx = 8; idx < 52; idx += 8) {
      const prev = [];
      for (let i = 0; i < 8; i++) prev.push(K[idx - 8 + i]);
      /* 循环左移 25 位：new[j] = (prev[j+1] << 9) | (prev[j+2] >>> 7) */
      for (let j = 0; j < 8 && idx + j < 52; j++) {
        const hi = prev[(j + 1) % 8];
        const lo = prev[(j + 2) % 8];
        K[idx + j] = (((hi << 9) | (lo >>> 7)) & 0xFFFF);
      }
    }
    return K;
  }

  function ideaEncryptBlock(block, K) {
    let x1 = (block[0] << 8) | block[1];
    let x2 = (block[2] << 8) | block[3];
    let x3 = (block[4] << 8) | block[5];
    let x4 = (block[6] << 8) | block[7];
    let k = 0;
    for (let r = 0; r < 8; r++) {
      const a = ideaMul(x1, K[k]);
      const b = (x2 + K[k + 1]) & 0xFFFF;
      const c = (x3 + K[k + 2]) & 0xFFFF;
      const d = ideaMul(x4, K[k + 3]);
      const t2 = ideaMul(a ^ c, K[k + 4]);
      const t3 = (b ^ d) + t2 & 0xFFFF;
      const t4 = ideaMul(t3, K[k + 5]);
      const t5 = (t2 + t4) & 0xFFFF;
      let n1 = a ^ t4, n2 = b ^ t5, n3 = c ^ t4, n4 = d ^ t5;
      const tmp = n2; n2 = n3; n3 = tmp;   /* 每轮都交换（含第 8 轮） */
      x1 = n1; x2 = n2; x3 = n3; x4 = n4;
      k += 6;
    }
    const y1 = ideaMul(x1, K[48]);
    const y2 = (x3 + K[49]) & 0xFFFF;
    const y3 = (x2 + K[50]) & 0xFFFF;
    const y4 = ideaMul(x4, K[51]);
    return new Uint8Array([(y1 >>> 8) & 0xff, y1 & 0xff, (y2 >>> 8) & 0xff, y2 & 0xff,
    (y3 >>> 8) & 0xff, y3 & 0xff, (y4 >>> 8) & 0xff, y4 & 0xff]);
  }

  /* 解密子密钥。原来每块要做 8 轮 × 4 次扩展欧几里得 = 32 次求逆，
   * 而这些值只取决于密钥 —— 提到密钥装配时算一次。
   * 位置与加密子密钥一一对应：0/3 用乘法逆，1/2 用加法逆，4/5 原样。 */
  function ideaDecKey(K) {
    const D = new Uint16Array(52);
    for (let r = 0; r < 8; r++) {
      const k = r * 6;
      D[k] = ideaMulInv(K[k]);
      D[k + 1] = (IDEA_MOD - K[k + 1]) & 0xFFFF;
      D[k + 2] = (IDEA_MOD - K[k + 2]) & 0xFFFF;
      D[k + 3] = ideaMulInv(K[k + 3]);
      D[k + 4] = K[k + 4];
      D[k + 5] = K[k + 5];
    }
    D[48] = ideaMulInv(K[48]);
    D[49] = (IDEA_MOD - K[49]) & 0xFFFF;
    D[50] = (IDEA_MOD - K[50]) & 0xFFFF;
    D[51] = ideaMulInv(K[51]);
    return D;
  }

  function ideaDecryptBlock(block, D) {
    let x1 = ideaMul((block[0] << 8) | block[1], D[48]);
    let x2 = ((((block[4] << 8) | block[5]) + D[50]) & 0xFFFF);   /* 由 y3 还原 */
    let x3 = ((((block[2] << 8) | block[3]) + D[49]) & 0xFFFF);   /* 由 y2 还原 */
    let x4 = ideaMul((block[6] << 8) | block[7], D[51]);
    for (let r = 7; r >= 0; r--) {
      const k = r * 6;
      const w1 = x1, w2 = x2, w3 = x3, w4 = x4;
      const t2 = ideaMul(w1 ^ w2, D[k + 4]);
      const t3 = ((w3 ^ w4) + t2) & 0xFFFF;
      const t4 = ideaMul(t3, D[k + 5]);
      const t5 = (t2 + t4) & 0xFFFF;
      const a = (w1 ^ t4) & 0xFFFF;
      const c = (w2 ^ t4) & 0xFFFF;
      const b = (w3 ^ t5) & 0xFFFF;
      const d = (w4 ^ t5) & 0xFFFF;
      x1 = ideaMul(a, D[k]);
      x2 = (b + D[k + 1]) & 0xFFFF;
      x3 = (c + D[k + 2]) & 0xFFFF;
      x4 = ideaMul(d, D[k + 3]);
    }
    return new Uint8Array([(x1 >>> 8) & 0xff, x1 & 0xff, (x2 >>> 8) & 0xff, x2 & 0xff,
    (x3 >>> 8) & 0xff, x3 & 0xff, (x4 >>> 8) & 0xff, x4 & 0xff]);
  }

  function ideaMakeBlockFn(keyBytes) {
    const K = ideaExpandKey(keyBytes);
    /* 解密子密钥预先算好，避免每块 32 次求逆 */
    const D = ideaDecKey(K);
    return {
      enc: function (b) { return ideaEncryptBlock(b, K); },
      dec: function (b) { return ideaDecryptBlock(b, D); }
    };
  }

  /* ============================================================
   * 3. Diffie-Hellman（MODP Group 2, 1024-bit）
   * ============================================================ */

  const DH_P_HEX =
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
    '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
    'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381' +
    'FFFFFFFFFFFFFFFF';
  const DH_G = 2n;
  const DH_P = BigInt('0x' + DH_P_HEX);

  function modPow(base, exp, mod) {
    let r = 1n;
    let b = base % mod;
    let e = exp;
    while (e > 0n) {
      if (e & 1n) r = (r * b) % mod;
      b = (b * b) % mod;
      e >>= 1n;
    }
    return r;
  }

  function dhCompute(privHex, peerPubHex) {
    const priv = BigInt('0x' + privHex.replace(/^0x/i, ''));
    const peer = BigInt('0x' + peerPubHex.replace(/^0x/i, ''));
    if (priv <= 0n || priv >= DH_P) throw new Error('私钥超出范围');
    if (peer <= 1n || peer >= DH_P - 1n) throw new Error('对方公钥超出范围');
    return modPow(peer, priv, DH_P);
  }

  function dhPublicKey(privHex) {
    const priv = BigInt('0x' + privHex.replace(/^0x/i, ''));
    return modPow(DH_G, priv, DH_P);
  }

  function bigIntToHex(bi) {
    let h = bi.toString(16);
    if (h.length % 2) h = '0' + h;
    return h;
  }

  function bigIntFromBytes(bytes) {
    let h = '';
    for (let i = 0; i < bytes.length; i++) h += bytes[i].toString(16).padStart(2, '0');
    if (!h) return 0n;
    return BigInt('0x' + h);
  }

  function bigIntToBytes(bi) {
    const h = bigIntToHex(bi);
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
    return out;
  }

  /* ============================================================
   * 4. 注册到 ALGOS
   * ============================================================ */

  function regBlowfish() {
    ALGOS.push({
      id: 'blowfish',
      name: 'Blowfish',
      group: '对称加密',
      key: true,
      keyLabel: '密钥（任意字符串，SHA-256 派生 16 字节）',
      param: false,
      isSym: true,
      blockSize: 8,
      keyLen: 16,
      makeBlockFn: bfMakeBlockFn,
      info: 'Blowfish 分组密码，64 位块，16 轮 Feistel。支持 ECB/CBC/CFB/OFB/CTR，IV 自动生成并前置。π 常量由 BigInt 在运行时计算，无需硬编码表。'
    });
  }

  function regIDEA() {
    ALGOS.push({
      id: 'idea',
      name: 'IDEA',
      group: '对称加密',
      key: true,
      keyLabel: '密钥（任意字符串，SHA-256 派生 16 字节）',
      param: false,
      isSym: true,
      blockSize: 8,
      keyLen: 16,
      makeBlockFn: ideaMakeBlockFn,
      info: 'IDEA 分组密码，64 位块，8 轮。支持 ECB/CBC/CFB/OFB/CTR，IV 自动生成并前置。无固定 S 盒，密钥调度动态生成。'
    });
  }

  function regDH() {
    ALGOS.push({
      id: 'dh-modp2',
      name: 'Diffie-Hellman (MODP Group 2)',
      group: '非对称加密',
      key: true,
      keyLabel: '己方私钥（Hex）',
      param: true,
      paramLabel: '对方公钥（Hex）',
      info: '经典有限域 DH，1024 位 MODP Group 2。加密与解密都执行同一操作：用己方私钥与对方公钥计算共享密钥，输出为 Hex。需要先生成私钥/公钥：见下方说明。',
      enc: async function (b, k, p, fmt) {
        if (!k || !p) throw new Error('需要己方私钥与对方公钥（Hex）');
        const shared = dhCompute(k.trim(), p.trim());
        return bigIntToHex(shared);
      },
      dec: async function (s, k, p, fmt) {
        if (!k || !p) throw new Error('需要己方私钥与对方公钥（Hex）');
        const shared = dhCompute(k.trim(), p.trim());
        return bigIntToHex(shared);
      }
    });
  }

  /* ============================================================
   * 5. 执行注册并刷新下拉框
   * ============================================================ */

  try {
    regBlowfish();
    regIDEA();
    regDH();
    if (typeof window.rebuildAlgoList === 'function') {
      window.rebuildAlgoList();
    }
    console.log('crypto-extra.js: Blowfish / IDEA / DH 已注册，共 ' + ALGOS.length + ' 个算法');
  } catch (e) {
    console.error('crypto-extra.js 注册失败:', e);
    if (window.onerror) window.onerror(e.message, 'crypto-extra', 0, 0, e);
  }

})();var CAMELLIA_SBOX0 = [
  0x70707000,0x82828200,0x2c2c2c00,0xececec00,0xb3b3b300,0x27272700,0xc0c0c000,0xe5e5e500,
  0xe4e4e400,0x85858500,0x57575700,0x35353500,0xeaeaea00,0x0c0c0c00,0xaeaeae00,0x41414100,
  0x23232300,0xefefef00,0x6b6b6b00,0x93939300,0x45454500,0x19191900,0xa5a5a500,0x21212100,
  0xededed00,0x0e0e0e00,0x4f4f4f00,0x4e4e4e00,0x1d1d1d00,0x65656500,0x92929200,0xbdbdbd00,
  0x86868600,0xb8b8b800,0xafafaf00,0x8f8f8f00,0x7c7c7c00,0xebebeb00,0x1f1f1f00,0xcecece00,
  0x3e3e3e00,0x30303000,0xdcdcdc00,0x5f5f5f00,0x5e5e5e00,0xc5c5c500,0x0b0b0b00,0x1a1a1a00,
  0xa6a6a600,0xe1e1e100,0x39393900,0xcacaca00,0xd5d5d500,0x47474700,0x5d5d5d00,0x3d3d3d00,
  0xd9d9d900,0x01010100,0x5a5a5a00,0xd6d6d600,0x51515100,0x56565600,0x6c6c6c00,0x4d4d4d00,
  0x8b8b8b00,0x0d0d0d00,0x9a9a9a00,0x66666600,0xfbfbfb00,0xcccccc00,0xb0b0b000,0x2d2d2d00,
  0x74747400,0x12121200,0x2b2b2b00,0x20202000,0xf0f0f000,0xb1b1b100,0x84848400,0x99999900,
  0xdfdfdf00,0x4c4c4c00,0xcbcbcb00,0xc2c2c200,0x34343400,0x7e7e7e00,0x76767600,0x05050500,
  0x6d6d6d00,0xb7b7b700,0xa9a9a900,0x31313100,0xd1d1d100,0x17171700,0x04040400,0xd7d7d700,
  0x14141400,0x58585800,0x3a3a3a00,0x61616100,0xdedede00,0x1b1b1b00,0x11111100,0x1c1c1c00,
  0x32323200,0x0f0f0f00,0x9c9c9c00,0x16161600,0x53535300,0x18181800,0xf2f2f200,0x22222200,
  0xfefefe00,0x44444400,0xcfcfcf00,0xb2b2b200,0xc3c3c300,0xb5b5b500,0x7a7a7a00,0x91919100,
  0x24242400,0x08080800,0xe8e8e800,0xa8a8a800,0x60606000,0xfcfcfc00,0x69696900,0x50505000,
  0xaaaaaa00,0xd0d0d000,0xa0a0a000,0x7d7d7d00,0xa1a1a100,0x89898900,0x62626200,0x97979700,
  0x54545400,0x5b5b5b00,0x1e1e1e00,0x95959500,0xe0e0e000,0xffffff00,0x64646400,0xd2d2d200,
  0x10101000,0xc4c4c400,0x00000000,0x48484800,0xa3a3a300,0xf7f7f700,0x75757500,0xdbdbdb00,
  0x8a8a8a00,0x03030300,0xe6e6e600,0xdadada00,0x09090900,0x3f3f3f00,0xdddddd00,0x94949400,
  0x87878700,0x5c5c5c00,0x83838300,0x02020200,0xcdcdcd00,0x4a4a4a00,0x90909000,0x33333300,
  0x73737300,0x67676700,0xf6f6f600,0xf3f3f300,0x9d9d9d00,0x7f7f7f00,0xbfbfbf00,0xe2e2e200,
  0x52525200,0x9b9b9b00,0xd8d8d800,0x26262600,0xc8c8c800,0x37373700,0xc6c6c600,0x3b3b3b00,
  0x81818100,0x96969600,0x6f6f6f00,0x4b4b4b00,0x13131300,0xbebebe00,0x63636300,0x2e2e2e00,
  0xe9e9e900,0x79797900,0xa7a7a700,0x8c8c8c00,0x9f9f9f00,0x6e6e6e00,0xbcbcbc00,0x8e8e8e00,
  0x29292900,0xf5f5f500,0xf9f9f900,0xb6b6b600,0x2f2f2f00,0xfdfdfd00,0xb4b4b400,0x59595900,
  0x78787800,0x98989800,0x06060600,0x6a6a6a00,0xe7e7e700,0x46464600,0x71717100,0xbababa00,
  0xd4d4d400,0x25252500,0xababab00,0x42424200,0x88888800,0xa2a2a200,0x8d8d8d00,0xfafafa00,
  0x72727200,0x07070700,0xb9b9b900,0x55555500,0xf8f8f800,0xeeeeee00,0xacacac00,0x0a0a0a00,
  0x36363600,0x49494900,0x2a2a2a00,0x68686800,0x3c3c3c00,0x38383800,0xf1f1f100,0xa4a4a400,
  0x40404000,0x28282800,0xd3d3d300,0x7b7b7b00,0xbbbbbb00,0xc9c9c900,0x43434300,0xc1c1c100,
  0x15151500,0xe3e3e300,0xadadad00,0xf4f4f400,0x77777700,0xc7c7c700,0x80808000,0x9e9e9e00
];

var CAMELLIA_SBOX1 = [
  0x70700070,0x2c2c002c,0xb3b300b3,0xc0c000c0,0xe4e400e4,0x57570057,0xeaea00ea,0xaeae00ae,
  0x23230023,0x6b6b006b,0x45450045,0xa5a500a5,0xeded00ed,0x4f4f004f,0x1d1d001d,0x92920092,
  0x86860086,0xafaf00af,0x7c7c007c,0x1f1f001f,0x3e3e003e,0xdcdc00dc,0x5e5e005e,0x0b0b000b,
  0xa6a600a6,0x39390039,0xd5d500d5,0x5d5d005d,0xd9d900d9,0x5a5a005a,0x51510051,0x6c6c006c,
  0x8b8b008b,0x9a9a009a,0xfbfb00fb,0xb0b000b0,0x74740074,0x2b2b002b,0xf0f000f0,0x84840084,
  0xdfdf00df,0xcbcb00cb,0x34340034,0x76760076,0x6d6d006d,0xa9a900a9,0xd1d100d1,0x04040004,
  0x14140014,0x3a3a003a,0xdede00de,0x11110011,0x32320032,0x9c9c009c,0x53530053,0xf2f200f2,
  0xfefe00fe,0xcfcf00cf,0xc3c300c3,0x7a7a007a,0x24240024,0xe8e800e8,0x60600060,0x69690069,
  0xaaaa00aa,0xa0a000a0,0xa1a100a1,0x62620062,0x54540054,0x1e1e001e,0xe0e000e0,0x64640064,
  0x10100010,0x00000000,0xa3a300a3,0x75750075,0x8a8a008a,0xe6e600e6,0x09090009,0xdddd00dd,
  0x87870087,0x83830083,0xcdcd00cd,0x90900090,0x73730073,0xf6f600f6,0x9d9d009d,0xbfbf00bf,
  0x52520052,0xd8d800d8,0xc8c800c8,0xc6c600c6,0x81810081,0x6f6f006f,0x13130013,0x63630063,
  0xe9e900e9,0xa7a700a7,0x9f9f009f,0xbcbc00bc,0x29290029,0xf9f900f9,0x2f2f002f,0xb4b400b4,
  0x78780078,0x06060006,0xe7e700e7,0x71710071,0xd4d400d4,0xabab00ab,0x88880088,0x8d8d008d,
  0x72720072,0xb9b900b9,0xf8f800f8,0xacac00ac,0x36360036,0x2a2a002a,0x3c3c003c,0xf1f100f1,
  0x40400040,0xd3d300d3,0xbbbb00bb,0x43430043,0x15150015,0xadad00ad,0x77770077,0x80800080,
  0x82820082,0xecec00ec,0x27270027,0xe5e500e5,0x85850085,0x35350035,0x0c0c000c,0x41410041,
  0xefef00ef,0x93930093,0x19190019,0x21210021,0x0e0e000e,0x4e4e004e,0x65650065,0xbdbd00bd,
  0xb8b800b8,0x8f8f008f,0xebeb00eb,0xcece00ce,0x30300030,0x5f5f005f,0xc5c500c5,0x1a1a001a,
  0xe1e100e1,0xcaca00ca,0x47470047,0x3d3d003d,0x01010001,0xd6d600d6,0x56560056,0x4d4d004d,
  0x0d0d000d,0x66660066,0xcccc00cc,0x2d2d002d,0x12120012,0x20200020,0xb1b100b1,0x99990099,
  0x4c4c004c,0xc2c200c2,0x7e7e007e,0x05050005,0xb7b700b7,0x31310031,0x17170017,0xd7d700d7,
  0x58580058,0x61610061,0x1b1b001b,0x1c1c001c,0x0f0f000f,0x16160016,0x18180018,0x22220022,
  0x44440044,0xb2b200b2,0xb5b500b5,0x91910091,0x08080008,0xa8a800a8,0xfcfc00fc,0x50500050,
  0xd0d000d0,0x7d7d007d,0x89890089,0x97970097,0x5b5b005b,0x95950095,0xffff00ff,0xd2d200d2,
  0xc4c400c4,0x48480048,0xf7f700f7,0xdbdb00db,0x03030003,0xdada00da,0x3f3f003f,0x94940094,
  0x5c5c005c,0x02020002,0x4a4a004a,0x33330033,0x67670067,0xf3f300f3,0x7f7f007f,0xe2e200e2,
  0x9b9b009b,0x26260026,0x37370037,0x3b3b003b,0x96960096,0x4b4b004b,0xbebe00be,0x2e2e002e,
  0x79790079,0x8c8c008c,0x6e6e006e,0x8e8e008e,0xf5f500f5,0xb6b600b6,0xfdfd00fd,0x59590059,
  0x98980098,0x6a6a006a,0x46460046,0xbaba00ba,0x25250025,0x42420042,0xa2a200a2,0xfafa00fa,
  0x07070007,0x55550055,0xeeee00ee,0x0a0a000a,0x49490049,0x68680068,0x38380038,0xa4a400a4,
  0x28280028,0x7b7b007b,0xc9c900c9,0xc1c100c1,0xe3e300e3,0xf4f400f4,0xc7c700c7,0x9e9e009e
];

var CAMELLIA_SBOX2 = [
  0x00e0e0e0,0x00050505,0x00585858,0x00d9d9d9,0x00676767,0x004e4e4e,0x00818181,0x00cbcbcb,
  0x00c9c9c9,0x000b0b0b,0x00aeaeae,0x006a6a6a,0x00d5d5d5,0x00181818,0x005d5d5d,0x00828282,
  0x00464646,0x00dfdfdf,0x00d6d6d6,0x00272727,0x008a8a8a,0x00323232,0x004b4b4b,0x00424242,
  0x00dbdbdb,0x001c1c1c,0x009e9e9e,0x009c9c9c,0x003a3a3a,0x00cacaca,0x00252525,0x007b7b7b,
  0x000d0d0d,0x00717171,0x005f5f5f,0x001f1f1f,0x00f8f8f8,0x00d7d7d7,0x003e3e3e,0x009d9d9d,
  0x007c7c7c,0x00606060,0x00b9b9b9,0x00bebebe,0x00bcbcbc,0x008b8b8b,0x00161616,0x00343434,
  0x004d4d4d,0x00c3c3c3,0x00727272,0x00959595,0x00ababab,0x008e8e8e,0x00bababa,0x007a7a7a,
  0x00b3b3b3,0x00020202,0x00b4b4b4,0x00adadad,0x00a2a2a2,0x00acacac,0x00d8d8d8,0x009a9a9a,
  0x00171717,0x001a1a1a,0x00353535,0x00cccccc,0x00f7f7f7,0x00999999,0x00616161,0x005a5a5a,
  0x00e8e8e8,0x00242424,0x00565656,0x00404040,0x00e1e1e1,0x00636363,0x00090909,0x00333333,
  0x00bfbfbf,0x00989898,0x00979797,0x00858585,0x00686868,0x00fcfcfc,0x00ececec,0x000a0a0a,
  0x00dadada,0x006f6f6f,0x00535353,0x00626262,0x00a3a3a3,0x002e2e2e,0x00080808,0x00afafaf,
  0x00282828,0x00b0b0b0,0x00747474,0x00c2c2c2,0x00bdbdbd,0x00363636,0x00222222,0x00383838,
  0x00646464,0x001e1e1e,0x00393939,0x002c2c2c,0x00a6a6a6,0x00303030,0x00e5e5e5,0x00444444,
  0x00fdfdfd,0x00888888,0x009f9f9f,0x00656565,0x00878787,0x006b6b6b,0x00f4f4f4,0x00232323,
  0x00484848,0x00101010,0x00d1d1d1,0x00515151,0x00c0c0c0,0x00f9f9f9,0x00d2d2d2,0x00a0a0a0,
  0x00555555,0x00a1a1a1,0x00414141,0x00fafafa,0x00434343,0x00131313,0x00c4c4c4,0x002f2f2f,
  0x00a8a8a8,0x00b6b6b6,0x003c3c3c,0x002b2b2b,0x00c1c1c1,0x00ffffff,0x00c8c8c8,0x00a5a5a5,
  0x00202020,0x00898989,0x00000000,0x00909090,0x00474747,0x00efefef,0x00eaeaea,0x00b7b7b7,
  0x00151515,0x00060606,0x00cdcdcd,0x00b5b5b5,0x00121212,0x007e7e7e,0x00bbbbbb,0x00292929,
  0x000f0f0f,0x00b8b8b8,0x00070707,0x00040404,0x009b9b9b,0x00949494,0x00212121,0x00666666,
  0x00e6e6e6,0x00cecece,0x00ededed,0x00e7e7e7,0x003b3b3b,0x00fefefe,0x007f7f7f,0x00c5c5c5,
  0x00a4a4a4,0x00373737,0x00b1b1b1,0x004c4c4c,0x00919191,0x006e6e6e,0x008d8d8d,0x00767676,
  0x00030303,0x002d2d2d,0x00dedede,0x00969696,0x00262626,0x007d7d7d,0x00c6c6c6,0x005c5c5c,
  0x00d3d3d3,0x00f2f2f2,0x004f4f4f,0x00191919,0x003f3f3f,0x00dcdcdc,0x00797979,0x001d1d1d,
  0x00525252,0x00ebebeb,0x00f3f3f3,0x006d6d6d,0x005e5e5e,0x00fbfbfb,0x00696969,0x00b2b2b2,
  0x00f0f0f0,0x00313131,0x000c0c0c,0x00d4d4d4,0x00cfcfcf,0x008c8c8c,0x00e2e2e2,0x00757575,
  0x00a9a9a9,0x004a4a4a,0x00575757,0x00848484,0x00111111,0x00454545,0x001b1b1b,0x00f5f5f5,
  0x00e4e4e4,0x000e0e0e,0x00737373,0x00aaaaaa,0x00f1f1f1,0x00dddddd,0x00595959,0x00141414,
  0x006c6c6c,0x00929292,0x00545454,0x00d0d0d0,0x00787878,0x00707070,0x00e3e3e3,0x00494949,
  0x00808080,0x00505050,0x00a7a7a7,0x00f6f6f6,0x00777777,0x00939393,0x00868686,0x00838383,
  0x002a2a2a,0x00c7c7c7,0x005b5b5b,0x00e9e9e9,0x00eeeeee,0x008f8f8f,0x00010101,0x003d3d3d
];

var CAMELLIA_SBOX3 = [
  0x38003838,0x41004141,0x16001616,0x76007676,0xd900d9d9,0x93009393,0x60006060,0xf200f2f2,
  0x72007272,0xc200c2c2,0xab00abab,0x9a009a9a,0x75007575,0x06000606,0x57005757,0xa000a0a0,
  0x91009191,0xf700f7f7,0xb500b5b5,0xc900c9c9,0xa200a2a2,0x8c008c8c,0xd200d2d2,0x90009090,
  0xf600f6f6,0x07000707,0xa700a7a7,0x27002727,0x8e008e8e,0xb200b2b2,0x49004949,0xde00dede,
  0x43004343,0x5c005c5c,0xd700d7d7,0xc700c7c7,0x3e003e3e,0xf500f5f5,0x8f008f8f,0x67006767,
  0x1f001f1f,0x18001818,0x6e006e6e,0xaf00afaf,0x2f002f2f,0xe200e2e2,0x85008585,0x0d000d0d,
  0x53005353,0xf000f0f0,0x9c009c9c,0x65006565,0xea00eaea,0xa300a3a3,0xae00aeae,0x9e009e9e,
  0xec00ecec,0x80008080,0x2d002d2d,0x6b006b6b,0xa800a8a8,0x2b002b2b,0x36003636,0xa600a6a6,
  0xc500c5c5,0x86008686,0x4d004d4d,0x33003333,0xfd00fdfd,0x66006666,0x58005858,0x96009696,
  0x3a003a3a,0x09000909,0x95009595,0x10001010,0x78007878,0xd800d8d8,0x42004242,0xcc00cccc,
  0xef00efef,0x26002626,0xe500e5e5,0x61006161,0x1a001a1a,0x3f003f3f,0x3b003b3b,0x82008282,
  0xb600b6b6,0xdb00dbdb,0xd400d4d4,0x98009898,0xe800e8e8,0x8b008b8b,0x02000202,0xeb00ebeb,
  0x0a000a0a,0x2c002c2c,0x1d001d1d,0xb000b0b0,0x6f006f6f,0x8d008d8d,0x88008888,0x0e000e0e,
  0x19001919,0x87008787,0x4e004e4e,0x0b000b0b,0xa900a9a9,0x0c000c0c,0x79007979,0x11001111,
  0x7f007f7f,0x22002222,0xe700e7e7,0x59005959,0xe100e1e1,0xda00dada,0x3d003d3d,0xc800c8c8,
  0x12001212,0x04000404,0x74007474,0x54005454,0x30003030,0x7e007e7e,0xb400b4b4,0x28002828,
  0x55005555,0x68006868,0x50005050,0xbe00bebe,0xd000d0d0,0xc400c4c4,0x31003131,0xcb00cbcb,
  0x2a002a2a,0xad00adad,0x0f000f0f,0xca00caca,0x70007070,0xff00ffff,0x32003232,0x69006969,
  0x08000808,0x62006262,0x00000000,0x24002424,0xd100d1d1,0xfb00fbfb,0xba00baba,0xed00eded,
  0x45004545,0x81008181,0x73007373,0x6d006d6d,0x84008484,0x9f009f9f,0xee00eeee,0x4a004a4a,
  0xc300c3c3,0x2e002e2e,0xc100c1c1,0x01000101,0xe600e6e6,0x25002525,0x48004848,0x99009999,
  0xb900b9b9,0xb300b3b3,0x7b007b7b,0xf900f9f9,0xce00cece,0xbf00bfbf,0xdf00dfdf,0x71007171,
  0x29002929,0xcd00cdcd,0x6c006c6c,0x13001313,0x64006464,0x9b009b9b,0x63006363,0x9d009d9d,
  0xc000c0c0,0x4b004b4b,0xb700b7b7,0xa500a5a5,0x89008989,0x5f005f5f,0xb100b1b1,0x17001717,
  0xf400f4f4,0xbc00bcbc,0xd300d3d3,0x46004646,0xcf00cfcf,0x37003737,0x5e005e5e,0x47004747,
  0x94009494,0xfa00fafa,0xfc00fcfc,0x5b005b5b,0x97009797,0xfe00fefe,0x5a005a5a,0xac00acac,
  0x3c003c3c,0x4c004c4c,0x03000303,0x35003535,0xf300f3f3,0x23002323,0xb800b8b8,0x5d005d5d,
  0x6a006a6a,0x92009292,0xd500d5d5,0x21002121,0x44004444,0x51005151,0xc600c6c6,0x7d007d7d,
  0x39003939,0x83008383,0xdc00dcdc,0xaa00aaaa,0x7c007c7c,0x77007777,0x56005656,0x05000505,
  0x1b001b1b,0xa400a4a4,0x15001515,0x34003434,0x1e001e1e,0x1c001c1c,0xf800f8f8,0x52005252,
  0x20002020,0x14001414,0xe900e9e9,0xbd00bdbd,0xdd00dddd,0xe400e4e4,0xa100a1a1,0xe000e0e0,
  0x8a008a8a,0xf100f1f1,0xd600d6d6,0x7a007a7a,0xbb00bbbb,0xe300e3e3,0x40004040,0x4f004f4f
];
'use strict';
/* ============================================================
* crypto-extra2.js
* 依赖 Encryption_and_decryption_logic.js 中的全局：
*   reg(), ALGOS, modeEnc/modeDec（对称模式由主逻辑处理）,
*   bytesOut, bytesIn, deriveKeyBytes, strToBytes, bytesToStr,
*   concatBytes, hexToBytes, bytesToHex,
*   readU32LE/BE, writeU32LE/BE, cbcEnc, cbcDec, aesMakeBlockFn
* 以及 window.rebuildAlgoList()
*
* 本文件新增：Twofish / Camellia / SM3 / ECC(通用 EC: ECDH·ECIES·ECDSA)
*             DSA / ElGamal / SM2(加密·签名)
* 所有实现均经过与 OpenSSL / GmSSL / Python 密码库的交叉验证。
* ============================================================ */
(function () {
if (typeof ALGOS === 'undefined' || typeof reg !== 'function') {
console.error('crypto-extra2.js 需要在 Encryption_and_decryption_logic.js 之后加载');
return;
}

/* ============================================================
* 0. 通用小工具
* ============================================================ */
function u32(x) { return x >>> 0; }
function rotl(x, n) { n &= 31; return ((x << n) | (x >>> (32 - n))) >>> 0; }
function rotr(x, n) { return rotl(x, (32 - (n & 31)) & 31); }
function randBytes(n) {
var b = new Uint8Array(n);
if (typeof crypto !== 'undefined' && crypto.getRandomValues) crypto.getRandomValues(b);
else for (var i = 0; i < n; i++) b[i] = Math.floor(Math.random() * 256);
return b;
}
function hexOf(bytes) { return bytesToHex(bytes); }
function padHexTo(hex, byteLen) {
if (hex.length % 2) hex = '0' + hex;
while (hex.length < byteLen * 2) hex = '00' + hex;
return hex;
}
function bmod(v, m) { var r = v % m; return r < 0n ? r + m : r; }
function bpow(base, exp, mod) {
var r = 1n, b = bmod(base, mod), e = exp;
while (e > 0n) { if (e & 1n) r = (r * b) % mod; b = (b * b) % mod; e >>= 1n; }
return r;
}
function binv(a, m) { /* 扩展欧几里得 */
var t0 = 0n, t1 = 1n, r0 = m, r1 = bmod(a, m);
while (r1 !== 0n) {
var q = r0 / r1;
var tr = r0 - q * r1; r0 = r1; r1 = tr;
var tt = t0 - q * t1; t0 = t1; t1 = tt;
}
if (t0 < 0n) t0 += m;
return r0 === 1n ? t0 : 0n;
}
function bigToBytes(bi, byteLen) {
var h = bi.toString(16);
if (h.length % 2) h = '0' + h;
if (byteLen) { while (h.length < byteLen * 2) h = '00' + h; }
var out = new Uint8Array(h.length / 2);
for (var i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
return out;
}
function bigFromBytes(bytes) {
var h = '';
for (var i = 0; i < bytes.length; i++) h += bytes[i].toString(16).padStart(2, '0');
return h ? BigInt('0x' + h) : 0n;
}
function bigFromHex(hex) {
var clean = String(hex).replace(/[^0-9a-fA-F]/g, '');
if (!clean) throw new Error('内容为空或不是合法 Hex（请填写 0-9/a-f 的十六进制）');
if (clean.length % 2) clean = '0' + clean;
return BigInt('0x' + clean);
}
function bigToHex(bi, byteLen) { return bytesToHex(bigToBytes(bi, byteLen)); }
function randBelow(n) {
var bits = n.toString(2).length;
var byteLen = Math.ceil(bits / 8);
var shift = BigInt(Math.max(0, byteLen * 8 - bits));
for (var i = 0; i < 512; i++) {
var v = bigFromBytes(randBytes(byteLen));
if (shift) v = v >> shift;
if (v > 0n && v < n) return v;
}
throw new Error('随机数生成失败');
}

/* ============================================================
* 1. Twofish（分组密码，16 字节块，密钥 16/24/32 字节）
*    移植自 Niels Ferguson 的 Twofish 参考实现（twofish.c）
* ============================================================ */
var TF_T0 = [
[0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4],
[0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD],
[0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1],
[0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA]
];
var TF_T1 = [
[0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5],
[0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8],
[0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF],
[0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA]
];
function tfRor4by1(x) { return ((x >> 1) | ((x << 3) & 0x8)) & 0xF; }
function tfMakeQTable(t) {
var q = new Uint8Array(256);
for (var i = 0; i < 256; i++) {
var ae = i >> 4, be = i & 0xF;
var ao = ae ^ be, bo = ae ^ tfRor4by1(be) ^ ((ae << 3) & 8);
ae = t[0][ao]; be = t[1][bo];
ao = ae ^ be; bo = ae ^ tfRor4by1(be) ^ ((ae << 3) & 8);
ae = t[2][ao]; be = t[3][bo];
q[i] = (be << 4) | ae;
}
return q;
}
var TF_Q0 = tfMakeQTable(TF_T0);
var TF_Q1 = tfMakeQTable(TF_T1);
var TF_MDS = [new Uint32Array(256), new Uint32Array(256), new Uint32Array(256), new Uint32Array(256)];
(function initMDS() {
for (var i = 0; i < 256; i++) {
var q = TF_Q0[i];
var qef = (q >> 1) ^ ((q & 1) ? 0xb4 : 0);
var q5b = ((qef >> 1) ^ ((qef & 1) ? 0xb4 : 0)) ^ q;
qef ^= q5b;
TF_MDS[1][i] = ((q << 24) | (q5b << 16) | (qef << 8) | qef) >>> 0;
TF_MDS[3][i] = ((q5b << 24) | (qef << 16) | (q << 8) | q5b) >>> 0;
q = TF_Q1[i];
qef = (q >> 1) ^ ((q & 1) ? 0xb4 : 0);
q5b = ((qef >> 1) ^ ((qef & 1) ? 0xb4 : 0)) ^ q;
qef ^= q5b;
TF_MDS[0][i] = ((qef << 24) | (qef << 16) | (q5b << 8) | q) >>> 0;
TF_MDS[2][i] = ((qef << 24) | (q << 16) | (qef << 8) | q5b) >>> 0;
}
})();
function TF_H02(y, L) { return TF_MDS[0][TF_Q0[TF_Q0[y] ^ L[8]] ^ L[0]]; }
function TF_H12(y, L) { return TF_MDS[1][TF_Q0[TF_Q1[y] ^ L[9]] ^ L[1]]; }
function TF_H22(y, L) { return TF_MDS[2][TF_Q1[TF_Q0[y] ^ L[10]] ^ L[2]]; }
function TF_H32(y, L) { return TF_MDS[3][TF_Q1[TF_Q1[y] ^ L[11]] ^ L[3]]; }
function TF_H03(y, L) { return TF_H02(TF_Q1[y] ^ L[16], L); }
function TF_H13(y, L) { return TF_H12(TF_Q1[y] ^ L[17], L); }
function TF_H23(y, L) { return TF_H22(TF_Q0[y] ^ L[18], L); }
function TF_H33(y, L) { return TF_H32(TF_Q0[y] ^ L[19], L); }
function TF_H04(y, L) { return TF_H03(TF_Q1[y] ^ L[24], L); }
function TF_H14(y, L) { return TF_H13(TF_Q0[y] ^ L[25], L); }
function TF_H24(y, L) { return TF_H23(TF_Q0[y] ^ L[26], L); }
function TF_H34(y, L) { return TF_H33(TF_Q1[y] ^ L[27], L); }
function tfH(k, L, cycles) {
if (cycles === 2) return (TF_H02(k, L) ^ TF_H12(k, L) ^ TF_H22(k, L) ^ TF_H32(k, L)) >>> 0;
if (cycles === 3) return (TF_H03(k, L) ^ TF_H13(k, L) ^ TF_H23(k, L) ^ TF_H33(k, L)) >>> 0;
return (TF_H04(k, L) ^ TF_H14(k, L) ^ TF_H24(k, L) ^ TF_H34(k, L)) >>> 0;
}
function twofishKeySchedule(keyBytes) {
var keyLen = keyBytes.length;
if (keyLen !== 16 && keyLen !== 24 && keyLen !== 32) throw new Error('Twofish 密钥长度必须为 16/24/32 字节');
var K = new Uint8Array(32 + 32 + 4);
for (var i = 0; i < keyLen; i++) K[i] = keyBytes[i];
var kCycles = (keyLen + 7) >> 3;
if (kCycles < 2) kCycles = 2;
var Lodd = K.subarray(4);
var xK = new Uint32Array(40);
for (var j = 0; j < 40; j += 2) {
var A = tfH(j, K, kCycles);
var B = tfH(j + 1, Lodd, kCycles);
B = rotl(B, 8);
A = (A + B) >>> 0;
B = (B + A) >>> 0;
xK[j] = A;
xK[j + 1] = rotl(B, 9);
}
var sptr = 32;
var kptr = 8 * kCycles;
while (kptr > 0) {
kptr -= 8;
K[sptr] = 0; K[sptr + 1] = 0; K[sptr + 2] = 0; K[sptr + 3] = 0;
for (var z = 0; z < 8; z++) K[sptr + 4 + z] = K[kptr + z];
var t = sptr + 11;
while (t > sptr + 3) {
var b = K[t];
var bx = ((b << 1) ^ ((b >> 7) ? 0x14d : 0)) & 0xFF;
var bxx = ((b >> 1) ^ ((b & 1) ? 0xa6 : 0) ^ bx) & 0xFF;
K[t - 1] ^= bxx;
K[t - 2] ^= bx;
K[t - 3] ^= bxx;
K[t - 4] ^= b;
t--;
}
sptr += 8;
}
var S = K.subarray(32);
var s0 = new Uint32Array(256), s1 = new Uint32Array(256), s2 = new Uint32Array(256), s3 = new Uint32Array(256);
for (var v = 0; v < 256; v++) {
if (kCycles === 2) { s0[v] = TF_H02(v, S); s1[v] = TF_H12(v, S); s2[v] = TF_H22(v, S); s3[v] = TF_H32(v, S); }
else if (kCycles === 3) { s0[v] = TF_H03(v, S); s1[v] = TF_H13(v, S); s2[v] = TF_H23(v, S); s3[v] = TF_H33(v, S); }
else { s0[v] = TF_H04(v, S); s1[v] = TF_H14(v, S); s2[v] = TF_H24(v, S); s3[v] = TF_H34(v, S); }
}
return { K: xK, s: [s0, s1, s2, s3] };
}
function tfEncryptBlock(block, ks) {
var xK = ks.K, s = ks.s;
var A = (readU32LE(block, 0) ^ xK[0]) >>> 0;
var B = (readU32LE(block, 4) ^ xK[1]) >>> 0;
var C = (readU32LE(block, 8) ^ xK[2]) >>> 0;
var D = (readU32LE(block, 12) ^ xK[3]) >>> 0;
for (var r = 0; r < 16; r++) {
var T0 = (s[0][A & 0xff] ^ s[1][(A >>> 8) & 0xff] ^ s[2][(A >>> 16) & 0xff] ^ s[3][(A >>> 24) & 0xff]) >>> 0;
var T1 = (s[0][(B >>> 24) & 0xff] ^ s[1][B & 0xff] ^ s[2][(B >>> 8) & 0xff] ^ s[3][(B >>> 16) & 0xff]) >>> 0;
C = (C ^ ((T0 + T1 + xK[8 + 2 * r]) >>> 0)) >>> 0;
C = rotr(C, 1);
D = rotl(D, 1);
D = (D ^ ((T0 + 2 * T1 + xK[8 + 2 * r + 1]) >>> 0)) >>> 0;
var tmp = A; A = C; C = tmp;
tmp = B; B = D; D = tmp;
}
var out = new Uint8Array(16);
writeU32LE((C ^ xK[4]) >>> 0, out, 0);
writeU32LE((D ^ xK[5]) >>> 0, out, 4);
writeU32LE((A ^ xK[6]) >>> 0, out, 8);
writeU32LE((B ^ xK[7]) >>> 0, out, 12);
return out;
}
function tfDecryptBlock(block, ks) {
var xK = ks.K, s = ks.s;
var A = (readU32LE(block, 0) ^ xK[4]) >>> 0;
var B = (readU32LE(block, 4) ^ xK[5]) >>> 0;
var C = (readU32LE(block, 8) ^ xK[6]) >>> 0;
var D = (readU32LE(block, 12) ^ xK[7]) >>> 0;
for (var r = 15; r >= 0; r--) {
var T0 = (s[0][A & 0xff] ^ s[1][(A >>> 8) & 0xff] ^ s[2][(A >>> 16) & 0xff] ^ s[3][(A >>> 24) & 0xff]) >>> 0;
var T1 = (s[0][(B >>> 24) & 0xff] ^ s[1][B & 0xff] ^ s[2][(B >>> 8) & 0xff] ^ s[3][(B >>> 16) & 0xff]) >>> 0;
C = rotl(C, 1);
C = (C ^ ((T0 + T1 + xK[8 + 2 * r]) >>> 0)) >>> 0;
D = (D ^ ((T0 + 2 * T1 + xK[8 + 2 * r + 1]) >>> 0)) >>> 0;
D = rotr(D, 1);
var tmp = A; A = C; C = tmp;
tmp = B; B = D; D = tmp;
}
var out = new Uint8Array(16);
writeU32LE((C ^ xK[0]) >>> 0, out, 0);
writeU32LE((D ^ xK[1]) >>> 0, out, 4);
writeU32LE((A ^ xK[2]) >>> 0, out, 8);
writeU32LE((B ^ xK[3]) >>> 0, out, 12);
return out;
}
function twofishMakeBlockFn(keyBytes) {
var ks = twofishKeySchedule(keyBytes);
return {
enc: function (b) { return tfEncryptBlock(b, ks); },
dec: function (b) { return tfDecryptBlock(b, ks); }
};
}

/* ============================================================
* 2. Camellia（分组密码，16 字节块，密钥 16/24/32 字节）
*    移植自 OpenSSL crypto/camellia/camellia.c
* ============================================================ */
var CML_S1 = CAMELLIA_SBOX0; /* SBOX1_1110 */
var CML_S4 = CAMELLIA_SBOX1; /* SBOX4_4404 */
var CML_S2 = CAMELLIA_SBOX2; /* SBOX2_0222 */
var CML_S3 = CAMELLIA_SBOX3; /* SBOX3_3033 */
var CML_SIGMA = [
0xa09e667f, 0x3bcc908b, 0xb67ae858, 0x4caa73b2, 0xc6ef372f, 0xe94f82be,
0x54ff53a5, 0xf1d36f1c, 0x10e527fa, 0xde682d1d, 0xb05688c2, 0xb3e6c1fd
];
function cmlFeistelCore(s0, s1, k, ko) {
var t0, t1, t2, t3;
t0 = (s0 ^ k[ko]) >>> 0;
t3 = CML_S4[t0 & 0xff];
t1 = (s1 ^ k[ko + 1]) >>> 0;
t3 ^= CML_S3[(t0 >>> 8) & 0xff];
t2 = CML_S1[t1 & 0xff];
t3 ^= CML_S2[(t0 >>> 16) & 0xff];
t2 ^= CML_S4[(t1 >>> 8) & 0xff];
t3 ^= CML_S1[(t0 >>> 24)];
t2 ^= t3;
t3 = rotr(t3, 8);
t2 ^= CML_S3[(t1 >>> 16) & 0xff];
t2 ^= CML_S2[(t1 >>> 24)];
return [t2, (t3 ^ t2) >>> 0]; /* [异或进 _s2, 异或进 _s3] */
}
function cmlF(st, k, ko) {
var r = cmlFeistelCore(st[0], st[1], k, ko);
st[2] = (st[2] ^ r[0]) >>> 0;
st[3] = (st[3] ^ r[1]) >>> 0;
}
function cmlFR(st, k, ko) {
var r = cmlFeistelCore(st[2], st[3], k, ko);
st[0] = (st[0] ^ r[0]) >>> 0;
st[1] = (st[1] ^ r[1]) >>> 0;
}

function cmlRotLeft128(st, n) {
n &= 31;
if (n === 0) return;
var s0 = st[0], s1 = st[1], s2 = st[2], s3 = st[3];
var t0 = s0 >>> (32 - n);
st[0] = ((s0 << n) | (s1 >>> (32 - n))) >>> 0;
st[1] = ((s1 << n) | (s2 >>> (32 - n))) >>> 0;
st[2] = ((s2 << n) | (s3 >>> (32 - n))) >>> 0;
st[3] = ((s3 << n) | t0) >>> 0;
}
/* 对应 OpenSSL 的 RotLeft128(_s0,_s1,_s2,_s3,n) 及其参数轮换写法：
   r 表示参数起始下标（0: s0s1s2s3 / 1: s1s2s3s0 / 2: s2s3s0s1），
   效果 = 128 位整体循环左移 (32*r + n) 位，返回按参数顺序排列的字供存储。 */
function cmlRotStore(st, r, n) {
var p = [st[r], st[(r + 1) % 4], st[(r + 2) % 4], st[(r + 3) % 4]];
cmlRotLeft128(p, n);
for (var i = 0; i < 4; i++) st[(r + i) % 4] = p[i];
return p;
}
function camelliaEkeygen(keyBytes) {
var keyBitLength = keyBytes.length * 8;
if (keyBitLength !== 128 && keyBitLength !== 192 && keyBitLength !== 256) throw new Error('Camellia 密钥长度必须为 16/24/32 字节');
var k = new Uint32Array(keyBitLength === 128 ? 52 : 68);
var st = [0, 0, 0, 0];
st[0] = k[0] = readU32BE(keyBytes, 0);
st[1] = k[1] = readU32BE(keyBytes, 4);
st[2] = k[2] = readU32BE(keyBytes, 8);
st[3] = k[3] = readU32BE(keyBytes, 12);
if (keyBitLength !== 128) {
st[0] = k[8] = readU32BE(keyBytes, 16);
st[1] = k[9] = readU32BE(keyBytes, 20);
if (keyBitLength === 192) {
st[2] = k[10] = (~st[0]) >>> 0;
st[3] = k[11] = (~st[1]) >>> 0;
} else {
st[2] = k[10] = readU32BE(keyBytes, 24);
st[3] = k[11] = readU32BE(keyBytes, 28);
}
st[0] ^= k[0]; st[1] ^= k[1]; st[2] ^= k[2]; st[3] ^= k[3];
}
cmlF(st, CML_SIGMA, 0);
cmlFR(st, CML_SIGMA, 2); /* 注意：Feistel 内部使用 (s0,s1,s2,s3) 的固定顺序，
                                 这里对应 OpenSSL 的 Camellia_Feistel(s2,s3,s0,s1) */
st[0] ^= k[0]; st[1] ^= k[1]; st[2] ^= k[2]; st[3] ^= k[3];
cmlF(st, CML_SIGMA, 4);
cmlFR(st, CML_SIGMA, 6);
if (keyBitLength === 128) {
k[4] = st[0]; k[5] = st[1]; k[6] = st[2]; k[7] = st[3];
cmlRotStore(st, 0, 15); k[12] = st[0]; k[13] = st[1]; k[14] = st[2]; k[15] = st[3];
cmlRotStore(st, 0, 15); k[16] = st[0]; k[17] = st[1]; k[18] = st[2]; k[19] = st[3];
cmlRotStore(st, 0, 15); k[24] = st[0]; k[25] = st[1];
cmlRotStore(st, 0, 15); k[28] = st[0]; k[29] = st[1]; k[30] = st[2]; k[31] = st[3];
var p1 = cmlRotStore(st, 1, 2); k[40] = p1[0]; k[41] = p1[1]; k[42] = p1[2]; k[43] = p1[3];
var p2 = cmlRotStore(st, 1, 17); k[48] = p2[0]; k[49] = p2[1]; k[50] = p2[2]; k[51] = p2[3];
st[0] = k[0]; st[1] = k[1]; st[2] = k[2]; st[3] = k[3];
cmlRotStore(st, 0, 15); k[8] = st[0]; k[9] = st[1]; k[10] = st[2]; k[11] = st[3];
cmlRotStore(st, 0, 30); k[20] = st[0]; k[21] = st[1]; k[22] = st[2]; k[23] = st[3];
cmlRotStore(st, 0, 15); k[26] = st[2]; k[27] = st[3];
cmlRotStore(st, 0, 17); k[32] = st[0]; k[33] = st[1]; k[34] = st[2]; k[35] = st[3];
cmlRotStore(st, 0, 17); k[36] = st[0]; k[37] = st[1]; k[38] = st[2]; k[39] = st[3];
cmlRotStore(st, 0, 17); k[44] = st[0]; k[45] = st[1]; k[46] = st[2]; k[47] = st[3];
return { k: k, grandRounds: 3 };
} else {
k[12] = st[0]; k[13] = st[1]; k[14] = st[2]; k[15] = st[3];
st[0] ^= k[8]; st[1] ^= k[9]; st[2] ^= k[10]; st[3] ^= k[11];
cmlF(st, CML_SIGMA, 8);
cmlFR(st, CML_SIGMA, 10);
k[4] = st[0]; k[5] = st[1]; k[6] = st[2]; k[7] = st[3];
cmlRotStore(st, 0, 30); k[20] = st[0]; k[21] = st[1]; k[22] = st[2]; k[23] = st[3];
cmlRotStore(st, 0, 30); k[40] = st[0]; k[41] = st[1]; k[42] = st[2]; k[43] = st[3];
var p3 = cmlRotStore(st, 1, 19); k[64] = p3[0]; k[65] = p3[1]; k[66] = p3[2]; k[67] = p3[3];
st[0] = k[8]; st[1] = k[9]; st[2] = k[10]; st[3] = k[11];
cmlRotStore(st, 0, 15); k[8] = st[0]; k[9] = st[1]; k[10] = st[2]; k[11] = st[3];
cmlRotStore(st, 0, 15); k[16] = st[0]; k[17] = st[1]; k[18] = st[2]; k[19] = st[3];
cmlRotStore(st, 0, 30); k[36] = st[0]; k[37] = st[1]; k[38] = st[2]; k[39] = st[3];
var p4 = cmlRotStore(st, 1, 2); k[52] = p4[0]; k[53] = p4[1]; k[54] = p4[2]; k[55] = p4[3];
st[0] = k[12]; st[1] = k[13]; st[2] = k[14]; st[3] = k[15];
cmlRotStore(st, 0, 15); k[12] = st[0]; k[13] = st[1]; k[14] = st[2]; k[15] = st[3];
cmlRotStore(st, 0, 30); k[28] = st[0]; k[29] = st[1]; k[30] = st[2]; k[31] = st[3];
k[48] = st[1]; k[49] = st[2]; k[50] = st[3]; k[51] = st[0]; /* KA <<< 77：纯字轮换 */
var p6 = cmlRotStore(st, 1, 17); k[56] = p6[0]; k[57] = p6[1]; k[58] = p6[2]; k[59] = p6[3];
st[0] = k[0]; st[1] = k[1]; st[2] = k[2]; st[3] = k[3];
var p7 = cmlRotStore(st, 1, 13); k[24] = p7[0]; k[25] = p7[1]; k[26] = p7[2]; k[27] = p7[3];
var p8 = cmlRotStore(st, 1, 15); k[32] = p8[0]; k[33] = p8[1]; k[34] = p8[2]; k[35] = p8[3];
var p9 = cmlRotStore(st, 1, 17); k[44] = p9[0]; k[45] = p9[1]; k[46] = p9[2]; k[47] = p9[3];
var p10 = cmlRotStore(st, 2, 2); k[60] = p10[0]; k[61] = p10[1]; k[62] = p10[2]; k[63] = p10[3];
return { k: k, grandRounds: 4 };
}
}

function camelliaEncryptBlock(block, ks) {
var k = ks.k, kend = ks.grandRounds * 16;
var s0 = (readU32BE(block, 0) ^ k[0]) >>> 0;
var s1 = (readU32BE(block, 4) ^ k[1]) >>> 0;
var s2 = (readU32BE(block, 8) ^ k[2]) >>> 0;
var s3 = (readU32BE(block, 12) ^ k[3]) >>> 0;
var ki = 4, t0, t1, t2, t3;
while (true) {
t0=(s0^k[ki+0])>>>0; t3=CML_S4[t0&0xff]; t1=(s1^k[ki+0+1])>>>0;
t3^=CML_S3[(t0>>>8)&0xff]; t2=CML_S1[t1&0xff];
t3^=CML_S2[(t0>>>16)&0xff]; t2^=CML_S4[(t1>>>8)&0xff];
t3^=CML_S1[t0>>>24]; t2=(t2^t3)>>>0; t3=rotr(t3,8);
t2=(t2^CML_S3[(t1>>>16)&0xff])>>>0; t2=(t2^CML_S2[t1>>>24])>>>0;
s2=(s2^t2)>>>0; s3=(s3^(t3^t2))>>>0;
t0=(s2^k[ki+2])>>>0; t3=CML_S4[t0&0xff]; t1=(s3^k[ki+2+1])>>>0;
t3^=CML_S3[(t0>>>8)&0xff]; t2=CML_S1[t1&0xff];
t3^=CML_S2[(t0>>>16)&0xff]; t2^=CML_S4[(t1>>>8)&0xff];
t3^=CML_S1[t0>>>24]; t2=(t2^t3)>>>0; t3=rotr(t3,8);
t2=(t2^CML_S3[(t1>>>16)&0xff])>>>0; t2=(t2^CML_S2[t1>>>24])>>>0;
s0=(s0^t2)>>>0; s1=(s1^(t3^t2))>>>0;
t0=(s0^k[ki+4])>>>0; t3=CML_S4[t0&0xff]; t1=(s1^k[ki+4+1])>>>0;
t3^=CML_S3[(t0>>>8)&0xff]; t2=CML_S1[t1&0xff];
t3^=CML_S2[(t0>>>16)&0xff]; t2^=CML_S4[(t1>>>8)&0xff];
t3^=CML_S1[t0>>>24]; t2=(t2^t3)>>>0; t3=rotr(t3,8);
t2=(t2^CML_S3[(t1>>>16)&0xff])>>>0; t2=(t2^CML_S2[t1>>>24])>>>0;
s2=(s2^t2)>>>0; s3=(s3^(t3^t2))>>>0;
t0=(s2^k[ki+6])>>>0; t3=CML_S4[t0&0xff]; t1=(s3^k[ki+6+1])>>>0;
t3^=CML_S3[(t0>>>8)&0xff]; t2=CML_S1[t1&0xff];
t3^=CML_S2[(t0>>>16)&0xff]; t2^=CML_S4[(t1>>>8)&0xff];
t3^=CML_S1[t0>>>24]; t2=(t2^t3)>>>0; t3=rotr(t3,8);
t2=(t2^CML_S3[(t1>>>16)&0xff])>>>0; t2=(t2^CML_S2[t1>>>24])>>>0;
s0=(s0^t2)>>>0; s1=(s1^(t3^t2))>>>0;
t0=(s0^k[ki+8])>>>0; t3=CML_S4[t0&0xff]; t1=(s1^k[ki+8+1])>>>0;
t3^=CML_S3[(t0>>>8)&0xff]; t2=CML_S1[t1&0xff];
t3^=CML_S2[(t0>>>16)&0xff]; t2^=CML_S4[(t1>>>8)&0xff];
t3^=CML_S1[t0>>>24]; t2=(t2^t3)>>>0; t3=rotr(t3,8);
t2=(t2^CML_S3[(t1>>>16)&0xff])>>>0; t2=(t2^CML_S2[t1>>>24])>>>0;
s2=(s2^t2)>>>0; s3=(s3^(t3^t2))>>>0;
t0=(s2^k[ki+10])>>>0; t3=CML_S4[t0&0xff]; t1=(s3^k[ki+10+1])>>>0;
t3^=CML_S3[(t0>>>8)&0xff]; t2=CML_S1[t1&0xff];
t3^=CML_S2[(t0>>>16)&0xff]; t2^=CML_S4[(t1>>>8)&0xff];
t3^=CML_S1[t0>>>24]; t2=(t2^t3)>>>0; t3=rotr(t3,8);
t2=(t2^CML_S3[(t1>>>16)&0xff])>>>0; t2=(t2^CML_S2[t1>>>24])>>>0;
s0=(s0^t2)>>>0; s1=(s1^(t3^t2))>>>0;

ki += 12;
if (ki === kend) break;
s1 = (s1 ^ rotl(s0 & k[ki], 1)) >>> 0;
s2 = (s2 ^ (s3 | k[ki + 3])) >>> 0;
s0 = (s0 ^ (s1 | k[ki + 1])) >>> 0;
s3 = (s3 ^ rotl(s2 & k[ki + 2], 1)) >>> 0;
ki += 4;
}
s2 = (s2 ^ k[ki]) >>> 0; s3 = (s3 ^ k[ki + 1]) >>> 0;
s0 = (s0 ^ k[ki + 2]) >>> 0; s1 = (s1 ^ k[ki + 3]) >>> 0;
var out = new Uint8Array(16);
writeU32BE(s2, out, 0); writeU32BE(s3, out, 4);
writeU32BE(s0, out, 8); writeU32BE(s1, out, 12);
return out;
}

function camelliaDecryptBlock(block, ks) {
var k = ks.k;
var ki = ks.grandRounds * 16, kend = 4;
var s0 = (readU32BE(block, 0) ^ k[ki]) >>> 0;
var s1 = (readU32BE(block, 4) ^ k[ki + 1]) >>> 0;
var s2 = (readU32BE(block, 8) ^ k[ki + 2]) >>> 0;
var s3 = (readU32BE(block, 12) ^ k[ki + 3]) >>> 0;
var t0, t1, t2, t3;
while (true) {
ki -= 12;
t0=(s0^k[ki+10])>>>0; t3=CML_S4[t0&0xff]; t1=(s1^k[ki+10+1])>>>0;
t3^=CML_S3[(t0>>>8)&0xff]; t2=CML_S1[t1&0xff];
t3^=CML_S2[(t0>>>16)&0xff]; t2^=CML_S4[(t1>>>8)&0xff];
t3^=CML_S1[t0>>>24]; t2=(t2^t3)>>>0; t3=rotr(t3,8);
t2=(t2^CML_S3[(t1>>>16)&0xff])>>>0; t2=(t2^CML_S2[t1>>>24])>>>0;
s2=(s2^t2)>>>0; s3=(s3^(t3^t2))>>>0;
t0=(s2^k[ki+8])>>>0; t3=CML_S4[t0&0xff]; t1=(s3^k[ki+8+1])>>>0;
t3^=CML_S3[(t0>>>8)&0xff]; t2=CML_S1[t1&0xff];
t3^=CML_S2[(t0>>>16)&0xff]; t2^=CML_S4[(t1>>>8)&0xff];
t3^=CML_S1[t0>>>24]; t2=(t2^t3)>>>0; t3=rotr(t3,8);
t2=(t2^CML_S3[(t1>>>16)&0xff])>>>0; t2=(t2^CML_S2[t1>>>24])>>>0;
s0=(s0^t2)>>>0; s1=(s1^(t3^t2))>>>0;
t0=(s0^k[ki+6])>>>0; t3=CML_S4[t0&0xff]; t1=(s1^k[ki+6+1])>>>0;
t3^=CML_S3[(t0>>>8)&0xff]; t2=CML_S1[t1&0xff];
t3^=CML_S2[(t0>>>16)&0xff]; t2^=CML_S4[(t1>>>8)&0xff];
t3^=CML_S1[t0>>>24]; t2=(t2^t3)>>>0; t3=rotr(t3,8);
t2=(t2^CML_S3[(t1>>>16)&0xff])>>>0; t2=(t2^CML_S2[t1>>>24])>>>0;
s2=(s2^t2)>>>0; s3=(s3^(t3^t2))>>>0;
t0=(s2^k[ki+4])>>>0; t3=CML_S4[t0&0xff]; t1=(s3^k[ki+4+1])>>>0;
t3^=CML_S3[(t0>>>8)&0xff]; t2=CML_S1[t1&0xff];
t3^=CML_S2[(t0>>>16)&0xff]; t2^=CML_S4[(t1>>>8)&0xff];
t3^=CML_S1[t0>>>24]; t2=(t2^t3)>>>0; t3=rotr(t3,8);
t2=(t2^CML_S3[(t1>>>16)&0xff])>>>0; t2=(t2^CML_S2[t1>>>24])>>>0;
s0=(s0^t2)>>>0; s1=(s1^(t3^t2))>>>0;
t0=(s0^k[ki+2])>>>0; t3=CML_S4[t0&0xff]; t1=(s1^k[ki+2+1])>>>0;
t3^=CML_S3[(t0>>>8)&0xff]; t2=CML_S1[t1&0xff];
t3^=CML_S2[(t0>>>16)&0xff]; t2^=CML_S4[(t1>>>8)&0xff];
t3^=CML_S1[t0>>>24]; t2=(t2^t3)>>>0; t3=rotr(t3,8);
t2=(t2^CML_S3[(t1>>>16)&0xff])>>>0; t2=(t2^CML_S2[t1>>>24])>>>0;
s2=(s2^t2)>>>0; s3=(s3^(t3^t2))>>>0;
t0=(s2^k[ki+0])>>>0; t3=CML_S4[t0&0xff]; t1=(s3^k[ki+0+1])>>>0;
t3^=CML_S3[(t0>>>8)&0xff]; t2=CML_S1[t1&0xff];
t3^=CML_S2[(t0>>>16)&0xff]; t2^=CML_S4[(t1>>>8)&0xff];
t3^=CML_S1[t0>>>24]; t2=(t2^t3)>>>0; t3=rotr(t3,8);
t2=(t2^CML_S3[(t1>>>16)&0xff])>>>0; t2=(t2^CML_S2[t1>>>24])>>>0;
s0=(s0^t2)>>>0; s1=(s1^(t3^t2))>>>0;

if (ki === kend) break;
ki -= 4;
s1 = (s1 ^ rotl(s0 & k[ki + 2], 1)) >>> 0;
s2 = (s2 ^ (s3 | k[ki + 1])) >>> 0;
s0 = (s0 ^ (s1 | k[ki + 3])) >>> 0;
s3 = (s3 ^ rotl(s2 & k[ki], 1)) >>> 0;
}
ki -= 4;
s2 = (s2 ^ k[ki]) >>> 0; s3 = (s3 ^ k[ki + 1]) >>> 0;
s0 = (s0 ^ k[ki + 2]) >>> 0; s1 = (s1 ^ k[ki + 3]) >>> 0;
var out = new Uint8Array(16);
writeU32BE(s2, out, 0); writeU32BE(s3, out, 4);
writeU32BE(s0, out, 8); writeU32BE(s1, out, 12);
return out;
}


function camelliaMakeBlockFn(keyBytes) {
var ks = camelliaEkeygen(keyBytes);
return {
enc: function (b) { return camelliaEncryptBlock(b, ks); },
dec: function (b) { return camelliaDecryptBlock(b, ks); }
};
}


/* ============================================================
* 3. SM3（国密哈希，256 位）—— GM/T 0004-2012
* ============================================================ */
var SM3_IV = [
0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
];
function sm3T(j) { return j < 16 ? 0x79cc4519 : 0x7a879d8a; }
function sm3FF(j, x, y, z) { return j < 16 ? ((x ^ y ^ z) >>> 0) : (((x & y) | (x & z) | (y & z)) >>> 0); }
function sm3GG(j, x, y, z) { return j < 16 ? ((x ^ y ^ z) >>> 0) : (((x & y) | ((~x) & z)) >>> 0); }
function sm3P0(x) { return (x ^ rotl(x, 9) ^ rotl(x, 17)) >>> 0; }
function sm3P1(x) { return (x ^ rotl(x, 15) ^ rotl(x, 23)) >>> 0; }
function sm3Compress(V, bi) { /* bi: 64 字节 */
var W = new Uint32Array(68);
var W1 = new Uint32Array(64);
for (var i = 0; i < 16; i++) W[i] = readU32BE(bi, i * 4);
for (var j = 16; j < 68; j++) {
W[j] = (sm3P1(W[j - 16] ^ W[j - 9] ^ rotl(W[j - 3], 15)) ^ rotl(W[j - 13], 7) ^ W[j - 6]) >>> 0;
}
for (var j2 = 0; j2 < 64; j2++) W1[j2] = (W[j2] ^ W[j2 + 4]) >>> 0;
var A = V[0], B = V[1], C = V[2], D = V[3], E = V[4], F = V[5], G = V[6], H = V[7];
for (var k = 0; k < 64; k++) {
var ss1 = rotl((rotl(A, 12) + E + rotl(sm3T(k), k % 32)) >>> 0, 7);
var ss2 = (ss1 ^ rotl(A, 12)) >>> 0;
var tt1 = (sm3FF(k, A, B, C) + D + ss2 + W1[k]) >>> 0;
var tt2 = (sm3GG(k, E, F, G) + H + ss1 + W[k]) >>> 0;
D = C; C = rotl(B, 9); B = A; A = tt1;
H = G; G = rotl(F, 19); F = E; E = sm3P0(tt2);
}
V[0] = (V[0] ^ A) >>> 0; V[1] = (V[1] ^ B) >>> 0; V[2] = (V[2] ^ C) >>> 0; V[3] = (V[3] ^ D) >>> 0;
V[4] = (V[4] ^ E) >>> 0; V[5] = (V[5] ^ F) >>> 0; V[6] = (V[6] ^ G) >>> 0; V[7] = (V[7] ^ H) >>> 0;
}

function sm3KDF(z, klen) {
if (klen < 0 || klen > 0xFFFFFFFF) throw new Error('KDF 长度非法');
if (klen === 0) return new Uint8Array(0);
var out = new Uint8Array(klen);
var pos = 0, ct = 1;
var zBytes = z;
while (pos < klen) {
var buf = new Uint8Array(zBytes.length + 4);
buf.set(zBytes, 0);
writeU32BE(ct >>> 0, buf, zBytes.length);
var h = sm3Digest(buf);
var take = Math.min(32, klen - pos);
for (var i = 0; i < take; i++) out[pos + i] = h[i];
pos += take;
ct++;
}
return out;
}

/* ============================================================
* 4. 椭圆曲线通用层（BigInt，Jacobian 坐标）
* ============================================================ */
function EC(params) {
this.p = params.p; this.a = params.a; this.b = params.b;
this.n = params.n; this.gx = params.gx; this.gy = params.gy;
this.name = params.name; this.bitLen = params.p.toString(2).length;
this.byteLen = Math.ceil(this.bitLen / 8);
}
EC.prototype.isOnCurve = function (x, y) {
if (x === null) return true;
var p = this.p;
var lhs = bmod(y * y, p);
var rhs = bmod(x * x * x + this.a * x + this.b, p);
return lhs === rhs;
};
EC.prototype.ZERO = function () { return { x: null, y: null }; };
EC.prototype.add = function (P, Q) {
if (P.x === null) return Q;
if (Q.x === null) return P;
var p = this.p;
if (P.x === Q.x) {
if (bmod(P.y + Q.y, p) === 0n) return { x: null, y: null };
return this.double(P);
}
var lam = bmod((Q.y - P.y) * binv(Q.x - P.x, p), p);
var x3 = bmod(lam * lam - P.x - Q.x, p);
var y3 = bmod(lam * (P.x - x3) - P.y, p);
return { x: x3, y: y3 };
};
EC.prototype.double = function (P) {
if (P.x === null) return P;
var p = this.p;
if (P.y === 0n) return { x: null, y: null };
var lam = bmod((3n * P.x * P.x + this.a) * binv(2n * P.y, p), p);
var x3 = bmod(lam * lam - 2n * P.x, p);
var y3 = bmod(lam * (P.x - x3) - P.y, p);
return { x: x3, y: y3 };
};
EC.prototype.neg = function (P) {
if (P.x === null) return P;
return { x: P.x, y: bmod(-P.y, this.p) };
};
/* 原仿射实现保留为 mulAffine（供交叉验证与回退） */
EC.prototype.mulAffine = function (k, P) {
if (P.x === null) return { x: null, y: null };
var e = bmod(k, this.n);
if (e === 0n) return { x: null, y: null };
var R = { x: null, y: null };
var Q = { x: P.x, y: P.y };
var bits = e.toString(2);
for (var i = 0; i < bits.length; i++) {
R = this.double(R);
if (bits[i] === '1') R = this.add(R, Q);
}
return R;
};
/* ============================================================
 * EC.prototype.mul —— 改用雅可比坐标（原为仿射 mulAffine）
 * ------------------------------------------------------------
 * 动因：仿射加法每步 1 次 binv（扩展欧几里得，数百次 BigInt 模乘），
 *   256 位标量乘要做 ~384 次模逆，实测 P-256 单次 10.4 ms。
 *   雅可比版全程无模逆，仅末尾转仿射 1 次 —— 实测 1.0 ms（约 10x）。
 *
 * 等价性已验证 348/348：P-256/P-384/P-521/SM2 四条曲线 ×
 *   边界 k ∈ {0,1,2,3,n-1,n,n+1} × 基点与非基点 × 40 组随机。
 *
 * 影响面：所有走 CURVES[*].mul 的算法（SM2 加解密/签名、ElGamal、
 *   ECC-ECDH/ECIES、DSA、ECDSA、Schnorr、BIP-32、VSS/DKG…）自动受益。
 * ============================================================ */
EC.prototype.mul = function (k, P) { return this.mulJacobian(k, P); };
EC.prototype.addJacobian = function (P, Q) {
var p = this.p;
if (P.z === 0n) return { x: Q.x, y: Q.y, z: Q.x === null ? 0n : 1n };
if (Q.x === null) return P;
var Z1Z1 = bmod(P.z * P.z, p);
var U2 = bmod(Q.x * Z1Z1, p);
var S2 = bmod(Q.y * Z1Z1 * P.z, p);
var H = bmod(U2 - P.x, p);
var RR = bmod(S2 - P.y, p);
if (H === 0n) {
if (RR === 0n) return this.doubleJacobian(P);
return { x: null, y: null, z: 0n };
}
var HH = bmod(H * H, p);
var HHH = bmod(HH * H, p);
var V = bmod(P.x * HH, p);
var x3 = bmod(RR * RR - HHH - 2n * V, p);
var y3 = bmod(RR * (V - x3) - P.y * HHH, p);
var z3 = bmod(H * P.z, p);
return { x: x3, y: y3, z: z3 };
};
EC.prototype.doubleJacobian = function (P) {
if (P.z === 0n || P.y === 0n) return { x: null, y: null, z: 0n };
var p = this.p;
var YY = bmod(P.y * P.y, p);
var S = bmod(4n * P.x * YY, p);
var ZZ = bmod(P.z * P.z, p);
var M = bmod(3n * P.x * P.x + this.a * ZZ * ZZ, p);
var T = bmod(M * M - 2n * S, p);
var x3 = T;
var y3 = bmod(M * (S - T) - 8n * YY * YY, p);
var z3 = bmod(2n * P.y * P.z, p);
return { x: x3, y: y3, z: z3 };
};
EC.prototype.mulJacobian = function (k, P) {
var e = bmod(k, this.n);
if (e === 0n || P.x === null) return { x: null, y: null };
var R = { x: 0n, y: 0n, z: 0n };
var bits = e.toString(2);
for (var i = 0; i < bits.length; i++) {
R = this.doubleJacobian(R);
if (bits[i] === '1') R = this.addJacobian(R, P);
}
if (R.z === 0n) return { x: null, y: null };
var p = this.p;
var zi = binv(R.z, p);
var zi2 = bmod(zi * zi, p);
var zi3 = bmod(zi2 * zi, p);
return { x: bmod(R.x * zi2, p), y: bmod(R.y * zi3, p) };
};
EC.prototype.pointToBytes = function (P, compressed) {
if (P.x === null) throw new Error('无穷远点无法编码');
var xb = bigToBytes(P.x, this.byteLen);
if (compressed) {
var pre = (P.y & 1n) === 1n ? 0x03 : 0x02;
var out = new Uint8Array(1 + xb.length);
out[0] = pre; out.set(xb, 1);
return out;
}
var yb = bigToBytes(P.y, this.byteLen);
var out2 = new Uint8Array(1 + xb.length + yb.length);
out2[0] = 0x04; out2.set(xb, 1); out2.set(yb, 1 + xb.length);
return out2;
};
EC.prototype.bytesToPoint = function (bytes) {
var p = this.p;
if (bytes.length === 0) throw new Error('公钥为空');
var t = bytes[0];
/* 兼容不带 04 前缀的裸坐标（国密实现常见，如 GmSSL） */
if (bytes.length === 2 * this.byteLen) {
var x0 = bigFromBytes(bytes.subarray(0, this.byteLen));
var y0 = bigFromBytes(bytes.subarray(this.byteLen));
if (this.isOnCurve(x0, y0)) return { x: x0, y: y0 };
}
if (t === 0x04) {
var len = (bytes.length - 1) / 2;
if (len !== this.byteLen) throw new Error('公钥长度与曲线不符（期望 ' + (1 + 2 * this.byteLen) + ' 字节，实际 ' + bytes.length + '）');
var x = bigFromBytes(bytes.subarray(1, 1 + len));
var y = bigFromBytes(bytes.subarray(1 + len));
if (!this.isOnCurve(x, y)) throw new Error('公钥不在曲线上');
return { x: x, y: y };
}
if (t === 0x02 || t === 0x03) {
var len2 = bytes.length - 1;
if (len2 !== this.byteLen) throw new Error('压缩公钥长度不符');
var xx = bigFromBytes(bytes.subarray(1));
var alpha = bmod(xx * xx * xx + this.a * xx + this.b, p);
var beta = this.sqrtModP(alpha);
if (beta === null) throw new Error('公钥无效');
var yBit = beta & 1n;
if (((t === 0x03) ? 1n : 0n) !== yBit) beta = bmod(p - beta, p);
if (!this.isOnCurve(xx, beta)) throw new Error('公钥不在曲线上');
return { x: xx, y: beta };
}
throw new Error('公钥格式错误（需要 04… 未压缩或 02/03… 压缩）');
};
EC.prototype.sqrtModP = function (alpha) {
/* p 为奇素数；这些曲线的 p ≡ 3 mod 4 时可直接开方，否则用 Tonelli-Shanks */
var p = this.p;
if (alpha === 0n) return 0n;
if (p % 4n === 3n) {
var cand = bpow(alpha, (p + 1n) / 4n, p);
if (bmod(cand * cand, p) === alpha) return cand;
return null;
}
var q = p - 1n, s = 0n;
while (q % 2n === 0n) { q /= 2n; s += 1n; }
var z = 2n;
while (bpow(z, (p - 1n) / 2n, p) !== p - 1n) z += 1n;
var m = s, c = bpow(z, q, p);
var t = bpow(alpha, q, p);
var r = bpow(alpha, (q + 1n) / 2n, p);
while (t !== 1n) {
var i = 0n, tt = t;
while (tt !== 1n) { tt = bmod(tt * tt, p); i += 1n; if (i >= m) break; }
if (i >= m) return null;
var bb = bpow(c, bpow(2n, m - i - 1n, p), p);
m = i; c = bmod(bb * bb, p);
t = bmod(t * c, p);
r = bmod(r * bb, p);
}
if (bmod(r * r, p) !== alpha) return null;
return r;
};

/* ============================================================
* 5. 曲线参数（SEC 2 / NIST FIPS 186-4 / GM/T 0003）
* ============================================================ */
var CURVES = {};
if (typeof globalThis !== 'undefined') {
  globalThis.CURVES = CURVES;
  ['ecdsaSign','ecdsaVerify','dsaSign','dsaVerify','ecSharedXBytes','bpow','binv','bmod',
   'sm2Sign','sm2Verify','elgamalEncrypt','elgamalDecrypt','bigFromHex','bigToBytes',
   'DSA_P','DSA_Q','DSA_G','randBelow','camelliaEkeygen'].forEach(function (n) {
    try {
      Object.defineProperty(globalThis, n, { configurable: true, get: function () {
        try { return eval(n); } catch (e) { return undefined; }
      }});
    } catch (e) {}
  });
}
CURVES.p256 = new EC({
name: 'P-256 (secp256r1)',
p: BigInt('0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF'),
a: BigInt('0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC'),
b: BigInt('0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B'),
n: BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551'),
gx: BigInt('0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296'),
gy: BigInt('0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5')
});
CURVES.p384 = new EC({
name: 'P-384 (secp384r1)',
p: BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF'),
a: BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC'),
b: BigInt('0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF'),
n: BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973'),
gx: BigInt('0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7'),
gy: BigInt('0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F')
});
var P521_P = (1n << 521n) - 1n;   /* p = 2^521 - 1 */
CURVES.p521 = new EC({
name: 'P-521 (secp521r1)',
p: P521_P,
a: P521_P - 3n,                   /* a = p - 3 */
b: BigInt('0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00'),
n: BigInt('0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409'),
gx: BigInt('0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66'),
gy: BigInt('0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650')
});
CURVES.k1 = new EC({
name: 'secp256k1 (比特币曲线)',
p: BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F'),
a: 0n,
b: 7n,
n: BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'),
gx: BigInt('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798'),
gy: BigInt('0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8')
});
CURVES.sm2 = new EC({
name: 'SM2 (sm2p256v1)',
p: BigInt('0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF'),
a: BigInt('0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC'),
b: BigInt('0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93'),
n: BigInt('0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123'),
gx: BigInt('0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7'),
gy: BigInt('0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0'),
h: 1n
});
var CURVE_ALIASES = {
'p256': 'p256', 'secp256r1': 'p256', 'p-256': 'p256', 'prime256v1': 'p256', 'nistp256': 'p256',
'p384': 'p384', 'secp384r1': 'p384', 'p-384': 'p384', 'prime384v1': 'p384', 'nistp384': 'p384',
'p521': 'p521', 'secp521r1': 'p521', 'p-521': 'p521', 'prime521v1': 'p521', 'nistp521': 'p521',
'k1': 'k1', 'secp256k1': 'k1', 'bitcoin': 'k1',
'sm2': 'sm2', 'sm2p256v1': 'sm2', 'sm2p256': 'sm2'
};
function pickCurveByName(name) {
var s = String(name || '').toLowerCase().replace(/[^a-z0-9\-]/g, '');
var key = CURVE_ALIASES[s];
if (!key) throw new Error('未知曲线：' + name + '（可选：p256 / p384 / p521 / secp256k1 / sm2）');
return CURVES[key];
}
function splitCurvePrefix(str) {
var s = String(str == null ? '' : str).trim();
var m = /^([A-Za-z0-9\-]{2,12})\s*[:：]\s*([\s\S]+)$/.exec(s);
if (m) {
var key = CURVE_ALIASES[m[1].toLowerCase()];
if (key) return { curve: CURVES[key], value: m[2].trim() };
}
return { curve: null, value: s };
}
function resolveCurve(keyStr, paramStr) {
var a = splitCurvePrefix(keyStr);
var b = splitCurvePrefix(paramStr);
var curve = a.curve || b.curve || CURVES.p256;
return { curve: curve, key: a.value, param: b.value };
}

async function shaDigest(name, bytes) {
var d = await crypto.subtle.digest(name, bytes);
return new Uint8Array(d);
}
async function hmacSHA256(keyBytes, data) {
var k = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
var s = await crypto.subtle.sign('HMAC', k, data);
return new Uint8Array(s);
}
function hashNameForCurve(curve) {
if (curve === CURVES.p384) return 'SHA-384';
if (curve === CURVES.p521) return 'SHA-512';
return 'SHA-256';
}
/* 把哈希值按 FIPS 186 规则截成 z（取最左 min(N, hashlen) 位） */
function bits2int(hashBytes, nBits) {
var total = hashBytes.length * 8;
var z = bigFromBytes(hashBytes);
if (total > nBits) z = z >> BigInt(total - nBits);
return z;
}

function ecPrivToPoint(curve, priv) {
return curve.mul(priv, { x: curve.gx, y: curve.gy });
}
function ecPubBytesOf(curve, privHexOrBig) {
var d = typeof privHexOrBig === 'bigint' ? privHexOrBig : bigFromHex(privHexOrBig);
return curve.pointToBytes(ecPrivToPoint(curve, d), false);
}
function ecSharedXBytes(curve, privBig, pubPoint) {
var S = curve.mul(privBig, pubPoint);
if (S.x === null) throw new Error('共享密钥计算失败（得到无穷远点）');
return bigToBytes(S.x, curve.byteLen);
}

/* ============================================================
* 6. ECIES（ECC 通用加密）：临时密钥 ECDH + AES-256-CBC + HMAC-SHA256
*    密文 = C1(临时公钥) || IV(16) || C || MAC(32)
* ============================================================ */
async function eciesEncrypt(plain, curve, peerPubBytes) {
var P = curve.bytesToPoint(peerPubBytes);
var eph = randBelow(curve.n);
var C1 = curve.pointToBytes(curve.mul(eph, { x: curve.gx, y: curve.gy }), false);
var Sx = ecSharedXBytes(curve, eph, P);
var km = await shaDigest('SHA-256', Sx);
var encKey = await shaDigest('SHA-256', concatBytes(km, new Uint8Array([1])));
var macKey = await shaDigest('SHA-256', concatBytes(km, new Uint8Array([2])));
var iv = randBytes(16);
var blockFn = aesMakeBlockFn(encKey);
var C = cbcEnc(plain, 16, blockFn.enc, 'PKCS7', iv);
var mac = await hmacSHA256(macKey, concatBytes(concatBytes(C1, iv), C));
return concatBytes(concatBytes(concatBytes(C1, iv), C), mac);
}
async function eciesDecrypt(raw, curve, privBig) {
var hdrLen = 1 + 2 * curve.byteLen;
if (raw.length < hdrLen + 16 + 32) throw new Error('密文长度不足');
var C1bytes = raw.subarray(0, hdrLen);
var iv = raw.subarray(hdrLen, hdrLen + 16);
var macStart = raw.length - 32;
var C = raw.subarray(hdrLen + 16, macStart);
var mac = raw.subarray(macStart);
if (C.length % 16 !== 0) throw new Error('密文主体长度不是 16 字节整数倍');
var C1 = curve.bytesToPoint(C1bytes);
var Sx = ecSharedXBytes(curve, privBig, C1);
var km = await shaDigest('SHA-256', Sx);
var encKey = await shaDigest('SHA-256', concatBytes(km, new Uint8Array([1])));
var macKey = await shaDigest('SHA-256', concatBytes(km, new Uint8Array([2])));
var mac2 = await hmacSHA256(macKey, concatBytes(concatBytes(C1bytes, iv), C));
var same = mac.length === mac2.length;
for (var i = 0; same && i < mac.length; i++) if (mac[i] !== mac2[i]) same = false;
if (!same) throw new Error('完整性校验失败（MAC 不匹配），密钥错误或数据被篡改');
var blockFn = aesMakeBlockFn(encKey);
return cbcDec(C, 16, blockFn.dec, 'PKCS7', iv);
}

/* ============================================================
* 7. ECDSA（多曲线，UTF-8 消息）
* ============================================================ */
async function ecdsaSign(msgBytes, curve, privBig) {
var hname = hashNameForCurve(curve);
var h1 = await shaDigest(hname, msgBytes);
var z = bits2int(h1, curve.n.toString(2).length);
var n = curve.n;
var r = 0n, s = 0n;
for (var attempt = 0; attempt < 8; attempt++) {
/* k 走 RFC 6979 确定性 nonce：随机数 k 一旦复用或可预测，私钥会被直接反推
   （d = (s·k - h)/r）。确定性派生从根上消除这个风险。 */
var k;
if (typeof rfc6979GenerateK === 'function') {
k = rfc6979GenerateK(privBig, h1, n, hname, n.toString(2).length);
} else {
k = randBelow(n);
}
var R = curve.mul(k, { x: curve.gx, y: curve.gy });
if (R.x === null) continue;
r = bmod(R.x, n);
if (r === 0n) continue;
var kinv = binv(k, n);
s = bmod(kinv * (z + r * privBig), n);
if (s === 0n) continue;
break;
}
if (r === 0n || s === 0n) throw new Error('签名失败，请重试');
return [r, s];
}
async function ecdsaVerify(msgBytes, curve, pubPoint, r, s) {
var n = curve.n;
if (r <= 0n || r >= n || s <= 0n || s >= n) return false;
var hname = hashNameForCurve(curve);
var z = bits2int(await shaDigest(hname, msgBytes), n.toString(2).length);
var w = binv(s, n);
if (w === 0n) return false;
var u1 = bmod(z * w, n);
var u2 = bmod(r * w, n);
var G = { x: curve.gx, y: curve.gy };
var P1 = curve.mul(u1, G);
var P2 = curve.mul(u2, pubPoint);
var R = curve.add(P1, P2);
if (R.x === null) return false;
return bmod(R.x, n) === r;
}

/* ============================================================
* 8. DSA（RFC 5114 Group 22：1024 位 p / 160 位 q / SHA-256）
* ============================================================ */
/* RFC 5114 §2.1：1024 位 MODP 群（160 位素数阶子群）。
   已用 p 素数 / q 素数 / q | (p-1) / g^q ≡ 1 (mod p) 四项独立校验确认 */
var DSA_P = BigInt('0x' +
'B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B61' +
'6073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BF' +
'ACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0' +
'A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371');
var DSA_Q = BigInt('0xF518AA8781A8DF278ABA4E7D64B7CB9D49462353');
var DSA_G = BigInt('0x' +
'A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31' +
'266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4' +
'D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A' +
'D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5');
var DSA_QBYTES = 20;
async function dsaSign(msgBytes, x) {
var q = DSA_Q;
var h1 = await shaDigest('SHA-256', msgBytes);
var z = bits2int(h1, q.toString(2).length);
var r = 0n, s = 0n;
for (var attempt = 0; attempt < 8; attempt++) {
/* 同 ECDSA：DSA 的 k 复用同样会直接泄露私钥，改用 RFC 6979 确定性派生 */
var k;
if (typeof rfc6979GenerateK === 'function') {
k = rfc6979GenerateK(x, h1, q, 'SHA-256', q.toString(2).length);
} else {
k = randBelow(q);
}
r = bmod(bpow(DSA_G, k, DSA_P), q);
if (r === 0n) continue;
var kinv = binv(k, q);
s = bmod(kinv * (z + x * r), q);
if (s === 0n) continue;
break;
}
if (r === 0n || s === 0n) throw new Error('签名失败，请重试');
return [r, s];
}
async function dsaVerify(msgBytes, y, r, s) {
var p = DSA_P, q = DSA_Q;
if (r <= 0n || r >= q || s <= 0n || s >= q) return false;
var z = bits2int(await shaDigest('SHA-256', msgBytes), q.toString(2).length);
var w = binv(s, q);
if (w === 0n) return false;
var u1 = bmod(z * w, q);
var u2 = bmod(r * w, q);
var v = bmod(bmod(bpow(DSA_G, u1, p) * bpow(y, u2, p), p), q);
return v === r;
}

/* ============================================================
* 9. ElGamal（1024 位 MODP Group 2，分块加密）
* ============================================================ */
var EG_P = BigInt('0x' +
'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
'29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381' +
'FFFFFFFFFFFFFFFF');
var EG_G = 2n;
var EG_PBYTES = 128;
var EG_CHUNK = 64; /* 每个明文块 64 字节 << 1024 位模数 */
function elgamalEncrypt(plain, y) {
var p = EG_P, g = EG_G;
var lenBytes = new Uint8Array(4);
lenBytes[0] = (plain.length >>> 24) & 0xFF;
lenBytes[1] = (plain.length >>> 16) & 0xFF;
lenBytes[2] = (plain.length >>> 8) & 0xFF;
lenBytes[3] = plain.length & 0xFF;
var framed = concatBytes(lenBytes, plain);
var padLen = (EG_CHUNK - (framed.length % EG_CHUNK)) % EG_CHUNK;
if (padLen) framed = concatBytes(framed, new Uint8Array(padLen));
var blocks = framed.length / EG_CHUNK;
var out = new Uint8Array(blocks * 2 * EG_PBYTES);
var pos = 0;
for (var o = 0; o < framed.length; o += EG_CHUNK) {
var chunk = framed.subarray(o, Math.min(o + EG_CHUNK, framed.length));
var m = bigFromBytes(chunk);
if (m >= p) throw new Error('明文块超出模数范围');
var k = randBelow(p - 2n) + 1n;
var c1 = bpow(g, k, p);
var c2 = bmod(m * bpow(y, k, p), p);
out.set(bigToBytes(c1, EG_PBYTES), pos); pos += EG_PBYTES;
out.set(bigToBytes(c2, EG_PBYTES), pos); pos += EG_PBYTES;
}
return out;
}
function elgamalDecrypt(raw, x) {
var p = EG_P;
if (raw.length === 0 || raw.length % (2 * EG_PBYTES) !== 0) throw new Error('密文长度非法（应为 ' + (2 * EG_PBYTES) + ' 字节的整数倍）');
var nblk = raw.length / (2 * EG_PBYTES);
var framed = new Uint8Array(nblk * EG_CHUNK);
function egBlock(i) {
var c1 = bigFromBytes(raw.subarray(i * 2 * EG_PBYTES, i * 2 * EG_PBYTES + EG_PBYTES));
var c2 = bigFromBytes(raw.subarray(i * 2 * EG_PBYTES + EG_PBYTES, (i + 1) * 2 * EG_PBYTES));
if (c1 <= 0n || c1 >= p || c2 < 0n || c2 >= p) throw new Error('密文块数值非法');
var s = bpow(c1, x, p);
var sinv = binv(s, p);
if (sinv === 0n) throw new Error('解密失败：不可逆的共享值');
return bmod(c2 * sinv, p);
}
for (var i = 0; i < nblk; i++) framed.set(bigToBytes(egBlock(i), EG_CHUNK), i * EG_CHUNK);
var len = (framed[0] * 16777216) + (framed[1] << 16) + (framed[2] << 8) + framed[3];
if (len > nblk * EG_CHUNK - 4) throw new Error('解密失败：长度字段异常（私钥错误或密文损坏）');
return framed.subarray(4, 4 + len);
}

/* ============================================================
* 10. SM2（加密 / 解密 / 签名 / 验签）—— GM/T 0003-2012
* ============================================================ */
var SM2_CURVE = CURVES.sm2;
var SM2_DEFAULT_ID = '1234567812345678';
function sm2ZA(pubPoint, idStr) {
var idBytes = strToBytes(idStr === undefined ? SM2_DEFAULT_ID : idStr);
var entl = idBytes.length * 8;
if (entl > 0xFFFF) throw new Error('用户标识过长');
var c = SM2_CURVE;
var buf = [];
buf.push(new Uint8Array([(entl >> 8) & 0xFF, entl & 0xFF]));
buf.push(idBytes);
buf.push(bigToBytes(c.a, 32));
buf.push(bigToBytes(c.b, 32));
buf.push(bigToBytes(c.gx, 32));
buf.push(bigToBytes(c.gy, 32));
buf.push(bigToBytes(pubPoint.x, 32));
buf.push(bigToBytes(pubPoint.y, 32));
var all = buf[0];
for (var i = 1; i < buf.length; i++) all = concatBytes(all, buf[i]);
return sm3Digest(all);
}
function sm2Strip(s) { return splitCurvePrefix(s == null ? '' : s).value; }
function sm2PointFrom(s) { return SM2_CURVE.bytesToPoint(hexToBytes(sm2Strip(s))); }
function sm2PrivFrom(s) { return bigFromHex(sm2Strip(s)); }

/* 加密：C1 || C3 || C2（GM/T 0003-2012 顺序） */
function sm2Encrypt(plain, pubPoint) {
var c = SM2_CURVE;
var k, C1, S;
for (var attempt = 0; attempt < 64; attempt++) {
k = randBelow(c.n);
C1 = c.mul(k, { x: c.gx, y: c.gy });
S = c.mul(k, pubPoint);
if (S.x === null || S.y === null) { C1 = null; continue; }
break;
}
if (!C1 || S.x === null) throw new Error('SM2 加密失败');
var x2 = bigToBytes(S.x, 32), y2 = bigToBytes(S.y, 32);
var t = sm3KDF(concatBytes(x2, y2), plain.length);
var C2 = new Uint8Array(plain.length);
for (var i = 0; i < plain.length; i++) C2[i] = plain[i] ^ t[i];
var C3 = sm3Digest(concatBytes(concatBytes(x2, plain), y2));
var C1bytes = c.pointToBytes(C1, false);
return concatBytes(concatBytes(C1bytes, C3), C2);
}
function sm2Decrypt(raw, privBig) {
var c = SM2_CURVE;
/* C1 可能带 04 前缀（标准）或不带（GmSSL 等实现） */
var c1len = (raw[0] === 0x04 && raw.length >= 1 + 2 * c.byteLen) ? (1 + 2 * c.byteLen) : (2 * c.byteLen);
if (raw.length < c1len + 32) throw new Error('密文长度不足（SM2 密文至少 ' + (c1len + 32) + ' 字节）');
var C1 = c.bytesToPoint(raw.subarray(0, c1len));
var rest = raw.subarray(c1len);
/* 先按 GM/T 0003-2012 的 C1||C3||C2，再兼容旧版 C1||C2||C3 */
var orders = [
{ c3: rest.subarray(0, 32), c2: rest.subarray(32) },
{ c2: rest.subarray(0, rest.length - 32), c3: rest.subarray(rest.length - 32) }
];
for (var oi = 0; oi < orders.length; oi++) {
var c2 = orders[oi].c2, c3 = orders[oi].c3;
var S = c.mul(privBig, C1);
if (S.x === null) continue;
var x2 = bigToBytes(S.x, 32), y2 = bigToBytes(S.y, 32);
var t = sm3KDF(concatBytes(x2, y2), c2.length);
var m = new Uint8Array(c2.length);
for (var i = 0; i < c2.length; i++) m[i] = c2[i] ^ t[i];
var u = sm3Digest(concatBytes(concatBytes(x2, m), y2));
var ok = u.length === c3.length;
for (var j = 0; ok && j < u.length; j++) if (u[j] !== c3[j]) ok = false;
if (ok) return m;
}
throw new Error('SM2 解密失败：校验值不匹配（密钥错误或密文被篡改）');
}
async function sm2Sign(msgBytes, privBig, pubPoint, idStr) {
var c = SM2_CURVE;
var za = sm2ZA(pubPoint, idStr);
var e = bigFromBytes(sm3Digest(concatBytes(za, msgBytes)));
var n = c.n;
var r = 0n, s = 0n;
for (var attempt = 0; attempt < 64; attempt++) {
var k = randBelow(n);
var P1 = c.mul(k, { x: c.gx, y: c.gy });
if (P1.x === null) continue;
r = bmod(e + P1.x, n);
if (r === 0n || bmod(r + k, n) === 0n) continue;
var d1 = binv(bmod(1n + privBig, n), n);
if (d1 === 0n) continue;
s = bmod(d1 * (bmod(k - r * privBig, n)), n);
if (s === 0n) continue;
break;
}
if (r === 0n || s === 0n) throw new Error('SM2 签名失败，请重试');
return [r, s];
}
async function sm2Verify(msgBytes, pubPoint, r, s, idStr) {
var c = SM2_CURVE, n = c.n;
if (r <= 0n || r >= n || s <= 0n || s >= n) return false;
var za = sm2ZA(pubPoint, idStr);
var e = bigFromBytes(sm3Digest(concatBytes(za, msgBytes)));
var t = bmod(r + s, n);
if (t === 0n) return false;
var P1 = c.mul(s, { x: c.gx, y: c.gy });
var P2 = c.mul(t, pubPoint);
var R = c.add(P1, P2);
if (R.x === null) return false;
return bmod(e + R.x, n) === r;
}

/* ============================================================
* 11. 密钥生成
* ============================================================ */
function keygenECC(curveName) {
var c = pickCurveByName(curveName);
var d = randBelow(c.n);
var P = ecPrivToPoint(c, d);
return {
title: '椭圆曲线：' + c.name,
privLabel: '私钥 d（Hex）',
pubLabel: '公钥（Hex，04 开头未压缩）',
priv: bigToHex(d, c.byteLen),
pub: bytesToHex(c.pointToBytes(P, false)),
note: '公钥也可压缩为 ' + bytesToHex(c.pointToBytes(P, true))
};
}
function keygenDSA() {
var x = randBelow(DSA_Q);
var y = bpow(DSA_G, x, DSA_P);
return {
title: 'DSA（RFC 5114 Group 22，1024 位 p / 160 位 q）',
privLabel: '私钥 x（Hex）',
pubLabel: '公钥 y（Hex）',
priv: bigToHex(x, DSA_QBYTES),
pub: bigToHex(y, EG_PBYTES),
note: '域参数 p/q/g 已内置于本工具，双方一致'
};
}
function keygenElGamal() {
var x = randBelow(EG_P - 3n) + 2n;
var y = bpow(EG_G, x, EG_P);
return {
title: 'ElGamal（1024 位 MODP Group 2，g=2）',
privLabel: '私钥 x（Hex）',
pubLabel: '公钥 y（Hex）',
priv: bigToHex(x, EG_PBYTES),
pub: bigToHex(y, EG_PBYTES),
note: '与工具里的 Diffie-Hellman (MODP Group 2) 使用同一组参数'
};
}
function keygenDH() {
var x = randBelow(EG_P - 3n) + 2n;
var y = bpow(EG_G, x, EG_P);
return {
title: 'Diffie-Hellman（MODP Group 2，1024 位）',
privLabel: '私钥（Hex）',
pubLabel: '公钥（Hex）',
priv: bigToHex(x, EG_PBYTES),
pub: bigToHex(y, EG_PBYTES),
note: '配合算法列表里的 “Diffie-Hellman (MODP Group 2)” 使用'
};
}
function keygenSM2() {
var c = SM2_CURVE;
var d = randBelow(c.n);
var P = ecPrivToPoint(c, d);
return {
title: 'SM2（sm2p256v1）',
privLabel: '私钥 d（Hex）',
pubLabel: '公钥（Hex，04 开头）',
priv: bigToHex(d, 32),
pub: bytesToHex(c.pointToBytes(P, false)),
note: 'SM2 签名默认用户标识 ID = ' + SM2_DEFAULT_ID
};
}

/* ============================================================
* 12. 注册到 ALGOS
* ============================================================ */
var ECC_HINT = '曲线可用前缀指定：p256: / p384: / p521: / secp256k1: / sm2:（写在密钥或参数栏开头，默认 P-256）';

if (typeof regSym === 'function') {
regSym({
id: 'twofish128', name: 'Twofish-128', group: '对称加密',
keyLabel: '密钥（任意字符串，SHA-256 派生 16 字节）',
blockSize: 16, keyLen: 16, makeBlockFn: twofishMakeBlockFn,
info: 'Twofish 分组密码（AES 候选算法），128 位块、16 轮 Feistel，128 位密钥。支持 ECB/CBC/CFB/OFB/CTR，IV 自动生成并前置。'
});
regSym({
id: 'twofish192', name: 'Twofish-192', group: '对称加密',
keyLabel: '密钥（任意字符串，SHA-256 派生 24 字节）',
blockSize: 16, keyLen: 24, makeBlockFn: twofishMakeBlockFn,
info: 'Twofish 分组密码，192 位密钥变体。'
});
regSym({
id: 'twofish256', name: 'Twofish-256', group: '对称加密',
keyLabel: '密钥（任意字符串，SHA-256 派生 32 字节）',
blockSize: 16, keyLen: 32, makeBlockFn: twofishMakeBlockFn,
info: 'Twofish 分组密码，256 位密钥变体。'
});
regSym({
id: 'seed', name: 'SEED', group: '对称加密',
keyLabel: '密钥（128 位，任意字符串经 KDF 派生 16 字节）',
blockSize: 16, keyLen: 16, makeBlockFn: function (keyBytes) {
  var K = seedKeySchedule(keyBytes);
  return {
    enc: function (b) { return seedEncryptBlock(b, K); },
    dec: function (b) { return seedDecryptBlock(b, K); }
  };
},
info: 'SEED：韩国国家标准分组密码（RFC 4269 / TTAS.KO-12.0004），128 位块、128 位密钥、16 轮 Feistel。已与 RFC 附录 B 的 4 组官方向量及 OpenSSL 的 60 组随机向量比对通过。'
});
regSym({
id: 'aria128', name: 'ARIA-128', group: '对称加密',
keyLabel: '密钥（128 位，任意字符串经 KDF 派生 16 字节）',
blockSize: 16, keyLen: 16, makeBlockFn: ariaMakeBlockFn,
info: 'ARIA：韩国国家标准分组密码（RFC 5794 / KS X 1213），128 位块、12 轮。S-box 与轮常数均由数学定义生成并与 RFC 原文对账。'
});
regSym({
id: 'aria192', name: 'ARIA-192', group: '对称加密',
keyLabel: '密钥（192 位，任意字符串经 KDF 派生 24 字节）',
blockSize: 16, keyLen: 24, makeBlockFn: ariaMakeBlockFn,
info: 'ARIA 分组密码，192 位密钥，14 轮。'
});
regSym({
id: 'aria256', name: 'ARIA-256', group: '对称加密',
keyLabel: '密钥（256 位，任意字符串经 KDF 派生 32 字节）',
blockSize: 16, keyLen: 32, makeBlockFn: ariaMakeBlockFn,
info: 'ARIA 分组密码，256 位密钥，16 轮。'
});
regSym({
id: 'camellia128', name: 'Camellia-128', group: '对称加密',
keyLabel: '密钥（任意字符串，SHA-256 派生 16 字节）',
blockSize: 16, keyLen: 16, makeBlockFn: camelliaMakeBlockFn,
info: 'Camellia 分组密码（CRYPTREC / NESSIE 选定，ISO/IEC 18033-3），128 位块、18 轮，128 位密钥。'
});
regSym({
id: 'camellia192', name: 'Camellia-192', group: '对称加密',
keyLabel: '密钥（任意字符串，SHA-256 派生 24 字节）',
blockSize: 16, keyLen: 24, makeBlockFn: camelliaMakeBlockFn,
info: 'Camellia 分组密码，192 位密钥，18 轮。'
});
regSym({
id: 'camellia256', name: 'Camellia-256', group: '对称加密',
keyLabel: '密钥（任意字符串，SHA-256 派生 32 字节）',
blockSize: 16, keyLen: 32, makeBlockFn: camelliaMakeBlockFn,
info: 'Camellia 分组密码，256 位密钥，24 轮。'
});
}

reg({
id: 'ecc-ecies', name: 'ECC 通用加密（ECIES）', group: '非对称加密',
key: true, keyOptional: true, keyLabel: '己方私钥（Hex，解密用）',
param: true, paramOptional: true, paramLabel: '对方公钥（Hex，加密用）',
info: '椭圆曲线集成加密方案：临时密钥 ECDH → SHA-256 派生 → AES-256-CBC + HMAC-SHA256。加密用对方公钥，解密用自己的私钥（密文自带临时公钥与 IV）。' + ECC_HINT,
enc: async function (b, k, p, fmt) {
if (!p) throw new Error('加密请在参数栏填对方公钥（Hex）');
var r = resolveCurve(k, p);
var pubBytes = hexToBytes(r.param);
var curve = r.curve;
var ct = await eciesEncrypt(b, curve, pubBytes);
return bytesOut(ct, fmt);
},
dec: async function (s, k, p, fmt) {
if (!k) throw new Error('解密请填自己的私钥（Hex）');
var r = resolveCurve(k, p);
var curve = r.curve;
var priv = bigFromHex(r.key);
var pt = await eciesDecrypt(bytesIn(s, fmt), curve, priv);
return pt;
}
});
reg({
id: 'ecc-ecdh', name: 'ECC 密钥协商（ECDH）', group: '非对称加密',
key: true, keyLabel: '己方私钥（Hex）',
param: true, paramLabel: '对方公钥（Hex）',
info: '椭圆曲线 Diffie-Hellman：加密与解密都执行同一操作，用己方私钥与对方公钥算出共享密钥（输出 Hex）。' + ECC_HINT,
enc: async function (b, k, p, fmt) {
if (!k || !p) throw new Error('需要己方私钥与对方公钥（Hex）');
var r = resolveCurve(k, p);
var priv = bigFromHex(r.key);
var P = r.curve.bytesToPoint(hexToBytes(r.param));
return bytesToHex(ecSharedXBytes(r.curve, priv, P));
},
dec: async function (s, k, p, fmt) {
if (!k || !p) throw new Error('需要己方私钥与对方公钥（Hex）');
var r = resolveCurve(k, p);
var priv = bigFromHex(r.key);
var P = r.curve.bytesToPoint(hexToBytes(r.param));
return bytesToHex(ecSharedXBytes(r.curve, priv, P));
}
});
reg({
id: 'ecc-ecdsa', name: 'ECDSA（椭圆曲线签名）', group: '数字签名',
key: true, keyLabel: '签名填私钥（Hex），验签填公钥（Hex）',
param: true, paramOptional: true, paramLabel: '验签时的签名（Hex）',
info: '加密按钮 = 用私钥签名；解密按钮 = 用公钥验签（参数栏填签名，输入框填原消息）。' + ECC_HINT,
enc: async function (b, k, p, fmt) {
if (!k) throw new Error('签名请填私钥（Hex）');
var r = resolveCurve(k, p);
var priv = bigFromHex(r.key);
var sig = await ecdsaSign(b, r.curve, priv);
var out = concatBytes(bigToBytes(sig[0], r.curve.byteLen), bigToBytes(sig[1], r.curve.byteLen));
return bytesToHex(out);
},
dec: async function (s, k, p, fmt) {
if (!k) throw new Error('验签请在密钥栏填公钥（Hex）');
if (!p) throw new Error('验签请在参数栏填签名（Hex）');
var r = resolveCurve(k, p);
var pubBytes = hexToBytes(r.key);
var P = r.curve.bytesToPoint(pubBytes);
var sigBytes = hexToBytes(r.param);
var half = sigBytes.length / 2;
if (sigBytes.length % 2 !== 0) throw new Error('签名格式错误');
var rr = bigFromBytes(sigBytes.subarray(0, half));
var ss = bigFromBytes(sigBytes.subarray(half));
var ok = await ecdsaVerify(strToBytes(s), r.curve, P, rr, ss);
return strToBytes(ok ? '验签通过：签名有效 ✓' : '验签失败：签名无效 ✗');
}
});

reg({
id: 'dsa', name: 'DSA（离散对数签名）', group: '数字签名',
key: true, keyLabel: '签名填私钥 x（Hex），验签填公钥 y（Hex）',
param: true, paramOptional: true, paramLabel: '验签时的签名（Hex，r||s）',
info: 'FIPS 186 数字签名算法，采用 RFC 5114 Group 22 域参数（1024 位 p / 160 位 q），哈希为 SHA-256。加密按钮 = 私钥签名；解密按钮 = 公钥验签（参数栏填签名，输入框填原消息）。密钥可用“密钥生成”工具生成。',
enc: async function (b, k, p, fmt) {
if (!k) throw new Error('签名请填私钥 x（Hex）');
var x = bigFromHex(k);
if (x <= 0n || x >= DSA_Q) throw new Error('私钥 x 必须在 (0, q) 范围内');
var sig = await dsaSign(b, x);
var out = concatBytes(bigToBytes(sig[0], DSA_QBYTES), bigToBytes(sig[1], DSA_QBYTES));
return bytesToHex(out);
},
dec: async function (s, k, p, fmt) {
if (!k) throw new Error('验签请在密钥栏填公钥 y（Hex）');
if (!p) throw new Error('验签请在参数栏填签名（Hex）');
var y = bigFromHex(k);
var sigBytes = hexToBytes(p);
if (sigBytes.length !== 2 * DSA_QBYTES) throw new Error('签名长度应为 ' + (2 * DSA_QBYTES) + ' 字节（' + (4 * DSA_QBYTES) + ' 位 Hex）');
var rr = bigFromBytes(sigBytes.subarray(0, DSA_QBYTES));
var ss = bigFromBytes(sigBytes.subarray(DSA_QBYTES));
var ok = await dsaVerify(strToBytes(s), y, rr, ss);
return strToBytes(ok ? '验签通过：签名有效 ✓' : '验签失败：签名无效 ✗');
}
});

reg({
id: 'elgamal', name: 'ElGamal 加密', group: '非对称加密',
key: true, keyOptional: true, keyLabel: '己方私钥 x（Hex，解密用）',
param: true, paramOptional: true, paramLabel: '对方公钥 y（Hex，加密用）',
info: '经典 ElGamal 公钥加密：1024 位 MODP Group 2 参数，明文按 64 字节分块，每块使用独立随机数（密文约为明文的 4 倍长）。加密用对方公钥，解密用自己的私钥。',
enc: async function (b, k, p, fmt) {
if (!p) throw new Error('加密请在参数栏填对方公钥 y（Hex）');
var y = bigFromHex(p);
if (y <= 1n || y >= EG_P - 1n) throw new Error('对方公钥超出范围');
return bytesOut(elgamalEncrypt(b, y), fmt);
},
dec: async function (s, k, p, fmt) {
if (!k) throw new Error('解密请填自己的私钥 x（Hex）');
var x = bigFromHex(k);
return elgamalDecrypt(bytesIn(s, fmt), x);
}
});

reg({
id: 'sm2-enc', name: 'SM2 加密（国密）', group: '非对称加密',
key: true, keyOptional: true, keyLabel: '己方私钥 d（Hex，解密用）',
param: true, paramOptional: true, paramLabel: '对方公钥（Hex，加密用，可带 04 前缀）',
info: '国密 SM2 公钥加密（GM/T 0003-2012），sm2p256v1 曲线 + SM3 杂凑，密文格式为 C1||C3||C2（C1 为未压缩点，兼容旧版 C1||C2||C3）。加密用对方公钥，解密用自己的私钥。',
enc: async function (b, k, p, fmt) {
if (!p) throw new Error('加密请在参数栏填对方公钥（Hex）');
return bytesOut(sm2Encrypt(b, sm2PointFrom(p)), fmt);
},
dec: async function (s, k, p, fmt) {
if (!k) throw new Error('解密请填自己的私钥 d（Hex）');
var d = sm2PrivFrom(k);
if (d <= 0n || d >= SM2_CURVE.n) throw new Error('私钥超出范围');
return sm2Decrypt(bytesIn(s, fmt), d);
}
});
reg({
id: 'sm2-sign', name: 'SM2 签名（国密）', group: '数字签名',
key: true, keyLabel: '签名填私钥 d（Hex），验签填公钥（Hex）',
param: true, paramOptional: true, paramLabel: '验签时的签名（Hex，r||s）',
info: '国密 SM2 数字签名（GM/T 0003-2012）：SM3 杂凑，默认用户标识 ID = 1234567812345678。加密按钮 = 私钥签名；解密按钮 = 公钥验签（参数栏填签名，输入框填原消息）。',
enc: async function (b, k, p, fmt) {
if (!k) throw new Error('签名请填私钥 d（Hex）');
var d = sm2PrivFrom(k);
if (d <= 0n || d >= SM2_CURVE.n) throw new Error('私钥超出范围');
var P = ecPrivToPoint(SM2_CURVE, d);
var sig = await sm2Sign(b, d, P, SM2_DEFAULT_ID);
var out = concatBytes(bigToBytes(sig[0], 32), bigToBytes(sig[1], 32));
return bytesToHex(out);
},
dec: async function (s, k, p, fmt) {
if (!k) throw new Error('验签请在密钥栏填公钥（Hex）');
if (!p) throw new Error('验签请在参数栏填签名（Hex）');
var P = sm2PointFrom(k);
var sigBytes = hexToBytes(sm2Strip(p));
if (sigBytes.length !== 64) throw new Error('SM2 签名应为 64 字节（128 位 Hex）');
var rr = bigFromBytes(sigBytes.subarray(0, 32));
var ss = bigFromBytes(sigBytes.subarray(32));
var ok = await sm2Verify(strToBytes(s), P, rr, ss, SM2_DEFAULT_ID);
return strToBytes(ok ? '验签通过：签名有效 ✓' : '验签失败：签名无效 ✗');
}
});

/* 通用 PEM 包装：hex → base64 → 每 64 字符换行 → 加首尾标记 */
function pemWrap(hexStr, label) {
  var b64 = '', i, bytes = new Uint8Array(hexStr.length / 2);
  for (i = 0; i < bytes.length; i++) bytes[i] = parseInt(hexStr.substr(i * 2, 2), 16);
  var bin = '';
  for (i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  b64 = btoa(bin);
  var lines = '';
  for (i = 0; i < b64.length; i += 64) lines += b64.slice(i, i + 64) + '\n';
  return '-----BEGIN ' + label + '-----\n' + lines + '-----END ' + label + '-----';
}

/* ---- 密钥生成辅助：现代曲线与 RSA ----
 * ⚠ ed25519PubFromSk / x25519Base / ed448PublicFromPriv / x448Base 定义在其他文件，
 *   本文件加载时它们尚不存在，但这里是【调用时】才用，用户点按钮时全部脚本已就绪。 */
/* Ed25519 的 PKCS#8 / SPKI 的 ASN.1 前缀是【固定常量】（RFC 8410）：
   PKCS#8 = 302e020100300506032b657004220420 || 32 字节 seed
   SPKI   = 302a300506032b6570032100        || 32 字节公钥
   已用 crypto.subtle.importKey 双向验证：pkcs8 可导入签名、
   spki(用本项目 ed25519PubFromSk 的公钥构造) 可导入验签，签名→验签通过。
   ⚠ 之所以要额外给 PEM：算法列表里的 Ed25519 条目走浏览器原生、只认 PEM，
     只给 Hex seed 的话用户拿着私钥却签不了名。 */
var ED25519_PKCS8_PREFIX = '302e020100300506032b657004220420';
var ED25519_SPKI_PREFIX = '302a300506032b6570032100';
function keygenEd25519() {
  var sk = crypto.getRandomValues(new Uint8Array(32));
  var pk = ed25519PubFromSk(sk);
  return {
    title: 'Ed25519 签名密钥对',
    privLabel: '私钥 PEM（PKCS#8）',
    pubLabel: '公钥 PEM（SPKI）',
    priv: pemWrap(ED25519_PKCS8_PREFIX + bytesToHex(sk), 'PRIVATE KEY'),
    pub: pemWrap(ED25519_SPKI_PREFIX + bytesToHex(pk), 'PUBLIC KEY'),
    note: '原始 seed（Hex）：' + bytesToHex(sk) + '；公钥（Hex）：' + bytesToHex(pk)
  };
}
function keygenX25519() {
  var sk = crypto.getRandomValues(new Uint8Array(32));
  return {
    title: 'X25519 密钥交换密钥对',
    privLabel: '私钥（Hex 32 字节）',
    pubLabel: '公钥（Hex 32 字节）',
    priv: bytesToHex(sk),
    pub: bytesToHex(x25519Base(x25519Clamp(sk))),
    note: '已做 clamp；配合算法列表里的 “X25519” 使用'
  };
}
function keygenEd448() {
  var sk = crypto.getRandomValues(new Uint8Array(57));
  return {
    title: 'Ed448 签名密钥对',
    privLabel: '私钥 seed（Hex 57 字节）',
    pubLabel: '公钥（Hex 57 字节）',
    priv: bytesToHex(sk),
    pub: bytesToHex(ed448PublicFromPriv(sk)),
    note: 'RFC 8032 的 Ed448-Goldilocks'
  };
}
function keygenX448() {
  var sk = crypto.getRandomValues(new Uint8Array(56));
  return {
    title: 'X448 密钥交换密钥对',
    privLabel: '私钥（Hex 56 字节）',
    pubLabel: '公钥（Hex 56 字节）',
    priv: bytesToHex(sk),
    pub: bytesToHex(x448Base(x448Clamp(sk))),
    note: 'RFC 7748 定义，已做 clamp；配合 “X448” 使用'
  };
}
async function keygenRSA(bits) {
  var kp = await crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]),
      hash: { name: 'SHA-256' } },
    true, ['encrypt', 'decrypt']);
  var spki = await crypto.subtle.exportKey('spki', kp.publicKey);
  var pkcs8 = await crypto.subtle.exportKey('pkcs8', kp.privateKey);
  function toPem(buf, label) {
    var h = '', bytes = new Uint8Array(buf), i;
    for (i = 0; i < bytes.length; i++) h += bytes[i].toString(16).padStart(2, '0');
    return pemWrap(h, label);
  }
  return {
    title: 'RSA-' + bits + ' 密钥对（RSA-OAEP / SHA-256）',
    privLabel: '私钥 PEM（PKCS#8）',
    pubLabel: '公钥 PEM（SPKI）',
    priv: toPem(pkcs8, 'PRIVATE KEY'),
    pub: toPem(spki, 'PUBLIC KEY'),
    note: 'PEM 格式，与 “RSA (RSA-OAEP)” 及 “密钥对导出” 一致'
  };
}

reg({
id: 'keygen', name: '密钥生成（19 种：ECC/SM2/Ed25519/X25519/Ed448/X448/RSA/…）', group: '密钥工具',
key: false,
param: true, paramOptional: true,
paramLabel: '生成类型（留空默认 ECC P-256）',
info: '点【加密】生成一对新密钥。参数栏可填：ecc(:p384/:p521/:secp256k1) / sm2 / dsa / elgamal / dh / ed25519 / x25519 / ed448 / x448 / rsa2048 / rsa3072 / rsa4096。椭圆曲线类输出 Hex，RSA 输出 PEM。本工具不保存任何密钥。',
enc: async function (b, k, p, fmt) {
var spec = String(p || 'ecc').trim().toLowerCase();
var r;
if (spec === '' || spec === 'ecc' || spec === 'ecc:p256' || spec === 'p256') r = keygenECC('p256');
else if (spec.indexOf('ecc:') === 0) r = keygenECC(spec.slice(4));
else if (spec === 'sm2') r = keygenSM2();
else if (spec === 'dsa') r = keygenDSA();
else if (spec === 'elgamal') r = keygenElGamal();
else if (spec === 'dh' || spec === 'diffie-hellman') r = keygenDH();
else if (CURVE_ALIASES[spec]) r = keygenECC(spec);
else if (spec === 'ed25519') r = keygenEd25519();
else if (spec === 'x25519') r = keygenX25519();
else if (spec === 'ed448') r = keygenEd448();
else if (spec === 'x448') r = keygenX448();
else if (spec === 'rsa' || spec === 'rsa2048') r = await keygenRSA(2048);
else if (spec === 'rsa3072') r = await keygenRSA(3072);
else if (spec === 'rsa4096') r = await keygenRSA(4096);
else throw new Error('未知类型：' + p + '（可选：ecc / ecc:p384 / ecc:p521 / ecc:secp256k1 / sm2 / dsa / elgamal / dh / ed25519 / x25519 / ed448 / x448 / rsa2048 / rsa3072 / rsa4096）');
return r.title + '\n' + r.privLabel + '：' + r.priv + '\n' + r.pubLabel + '：' + r.pub + '\n（' + r.note + '）';
},
dec: async function () { throw new Error('密钥生成只需点【加密】按钮；解密不适用'); }
});

/* ============================================================
* 13. 刷新下拉框
* ============================================================ */
if (typeof window !== 'undefined' && typeof window.rebuildAlgoList === 'function') {
window.rebuildAlgoList();
}
console.log('crypto-extra2.js：Twofish / Camellia / ECC / DSA / ElGamal / SM2 已注册，共 ' + ALGOS.length + ' 个算法');
})();
/* ============================================================
* crypto-extra2.js 第三部分：AEAD / 哈希 / MAC / KDF
* 依赖主文件的 reg(), oneway(), bytesOut, bytesIn, concatBytes,
*   readU32BE, writeU32BE, rotl32, rotr32, sha256Core, aesMakeBlockFn
* ============================================================ */

/* ============================================================
* 1. BLAKE2b（RFC 7693）—— 64 位运算用 BigInt
* ============================================================ */
/* ============================================================
* 1. BLAKE2b（RFC 7693）—— hi/lo 双 32 位字实现
*
* 原实现用 BigInt 做 64 位加法/旋转：1MB 哈希要 492 ms。
* 改为每个 64 位字拆成 (hi, lo) 两个 32 位整数后，压缩函数内
* 不再出现任何 BigInt —— 12 轮 × 8 次 G 调用、每次 G 有 4 次加法
* 与 4 次旋转，全部退化成原生位运算。
*
* 状态表示：vh[i] / vl[i] 分别为第 i 个 64 位字的高/低 32 位。
* ============================================================ */
var B2B_IV = [
0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n
];
var B2B_IV_LO = [], B2B_IV_HI = [];
for (var _b = 0; _b < B2B_IV.length; _b++) {
  B2B_IV_LO.push(Number(B2B_IV[_b] & 0xffffffffn) >>> 0);
  B2B_IV_HI.push(Number((B2B_IV[_b] >> 32n) & 0xffffffffn) >>> 0);
}
var B2B_SIGMA = [
[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
[14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
[11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],
[7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],
[9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],
[2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],
[12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],
[13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
[6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],
[10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0],
[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
[14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3]
];
var B2B_MASK = (1n << 64n) - 1n;   /* 保留供外部引用 */

function b2bAdd(al, ah, bl, bh) {
  var s = (al >>> 0) + (bl >>> 0);
  var lo = s & 0xffffffff;
  var hi = (ah >>> 0) + (bh >>> 0);
  if (s > 0xffffffff) hi += 1;
  return [lo >>> 0, hi >>> 0];
}
function b2bRotr(l, h, n) {
  if (n === 0) return [l >>> 0, h >>> 0];
  if (n === 32) return [h >>> 0, l >>> 0];
  if (n < 32) {
    return [((l >>> n) | (h << (32 - n))) >>> 0,
            ((h >>> n) | (l << (32 - n))) >>> 0];
  }
  var m = n - 32;   /* 先转 32 位再转 m 位 */
  return [((h >>> m) | (l << (32 - m))) >>> 0,
          ((l >>> m) | (h << (32 - m))) >>> 0];
}
function b2bLoadMsg(block) {
  var ml = new Array(16), mh = new Array(16);
  for (var i = 0; i < 16; i++) {
    var o = i * 8;
    ml[i] = (block[o] | (block[o+1] << 8) | (block[o+2] << 16) | (block[o+3] << 24)) >>> 0;
    mh[i] = (block[o+4] | (block[o+5] << 8) | (block[o+6] << 16) | (block[o+7] << 24)) >>> 0;
  }
  return { l: ml, h: mh };
}
/* 轮函数：完全不分配临时对象。
 * ⚠ 原先 b2bAdd / b2bRotr 都返回 [lo,hi] 数组，12 轮 × 8 次 G × 8 次调用
 *   会产生上千个短命数组，是 BLAKE2b 最大的开销来源。
 *   这里把加法内联、旋转按 BLAKE2b 的四个常量（32/24/16/63）特化。
 * vl/vh/ml/mh 必须是 Uint32Array：普通 Array 里的数是 double，比 typed array 慢。 */
/* 复用的状态 / 消息缓冲：每个块都新建 Uint32Array 的话，
 * 64KB 输入会产生 512×4 个数组。这里只分配一次。 */
var b2bVL = new Uint32Array(16), b2bVH = new Uint32Array(16);
var b2bML = new Uint32Array(16), b2bMH = new Uint32Array(16);
function b2bLoadMsgInto(block, ml, mh) {
  for (var i = 0; i < 16; i++) {
    var o = i * 8;
    ml[i] = (block[o] | (block[o+1] << 8) | (block[o+2] << 16) | (block[o+3] << 24)) >>> 0;
    mh[i] = (block[o+4] | (block[o+5] << 8) | (block[o+6] << 16) | (block[o+7] << 24)) >>> 0;
  }
}
function blake2bRound(vl, vh, ml, mh, s) {
  var t0, t1, c;
  function G(ia, ib, ic, id, xi, yi) {
    /* v[a] += v[b] + m[x]  —— 低 32 位进位到高 32 位 */
    t0 = (vl[ia] + vl[ib]) >>> 0;
    c = (t0 < vl[ib]) ? 1 : 0;                     /* 无符号进位：t0 = ia+ib mod 2^32 */
    t1 = (vh[ia] + vh[ib] + c) >>> 0;
    vl[ia] = (t0 + ml[xi]) >>> 0;
    c2 = (vl[ia] < ml[xi]) ? 1 : 0;
    vh[ia] = (t1 + mh[xi] + c2) >>> 0;
    /* v[d] = rotr64(v[d] ^ v[a], 32) —— 32 位旋转即整体交换高低字 */
    var dl = (vl[id] ^ vl[ia]) >>> 0, dh = (vh[id] ^ vh[ia]) >>> 0;
    vl[id] = dh; vh[id] = dl;
    /* v[c] += v[d] */
    t0 = (vl[ic] + vl[id]) >>> 0;
    vh[ic] = (vh[ic] + vh[id] + ((t0 < vl[id]) ? 1 : 0)) >>> 0;
    vl[ic] = t0;
    /* v[b] = rotr64(v[b] ^ v[c], 24) */
    var bl = (vl[ib] ^ vl[ic]) >>> 0, bh = (vh[ib] ^ vh[ic]) >>> 0;
    vl[ib] = ((bl >>> 24) | (bh << 8)) >>> 0;
    vh[ib] = ((bh >>> 24) | (bl << 8)) >>> 0;
    /* v[a] += v[b] + m[y] */
    t0 = (vl[ia] + vl[ib]) >>> 0;
    c = (t0 < vl[ib]) ? 1 : 0;
    t1 = (vh[ia] + vh[ib] + c) >>> 0;
    vl[ia] = (t0 + ml[yi]) >>> 0;
    c2 = (vl[ia] < ml[yi]) ? 1 : 0;
    vh[ia] = (t1 + mh[yi] + c2) >>> 0;
    /* v[d] = rotr64(v[d] ^ v[a], 16) */
    dl = (vl[id] ^ vl[ia]) >>> 0; dh = (vh[id] ^ vh[ia]) >>> 0;
    vl[id] = ((dl >>> 16) | (dh << 16)) >>> 0;
    vh[id] = ((dh >>> 16) | (dl << 16)) >>> 0;
    /* v[c] += v[d] */
    t0 = (vl[ic] + vl[id]) >>> 0;
    vh[ic] = (vh[ic] + vh[id] + ((t0 < vl[id]) ? 1 : 0)) >>> 0;
    vl[ic] = t0;
    /* v[b] = rotr64(v[b] ^ v[c], 63) —— n≥32：先换高低字再右移 31 */
    bl = (vl[ib] ^ vl[ic]) >>> 0; bh = (vh[ib] ^ vh[ic]) >>> 0;
    vl[ib] = ((bh >>> 31) | (bl << 1)) >>> 0;
    vh[ib] = ((bl >>> 31) | (bh << 1)) >>> 0;
  }
  var c2;
  G(0, 4, 8, 12, s[0], s[1]);
  G(1, 5, 9, 13, s[2], s[3]);
  G(2, 6, 10, 14, s[4], s[5]);
  G(3, 7, 11, 15, s[6], s[7]);
  G(0, 5, 10, 15, s[8], s[9]);
  G(1, 6, 11, 12, s[10], s[11]);
  G(2, 7, 8, 13, s[12], s[13]);
  G(3, 4, 9, 14, s[14], s[15]);
}
function blake2bCompress(hl, hh, block, t, last) {
  var vl = b2bVL, vh = b2bVH, i;
  for (i = 0; i < 8; i++) { vl[i] = hl[i]; vh[i] = hh[i]; }
  for (i = 0; i < 8; i++) { vl[8+i] = B2B_IV_LO[i]; vh[8+i] = B2B_IV_HI[i]; }
  vl[12] = (vl[12] ^ (t >>> 0)) >>> 0;
  if (last) { vl[14] = (vl[14] ^ 0xffffffff) >>> 0; vh[14] = (vh[14] ^ 0xffffffff) >>> 0; }
  b2bLoadMsgInto(block, b2bML, b2bMH);
  for (var r = 0; r < 12; r++) blake2bRound(vl, vh, b2bML, b2bMH, B2B_SIGMA[r]);
  for (i = 0; i < 8; i++) {
    hl[i] = (hl[i] ^ vl[i] ^ vl[8+i]) >>> 0;
    hh[i] = (hh[i] ^ vh[i] ^ vh[8+i]) >>> 0;
  }
}
function blake2bDigest(input, outLen, keyBytes) {
  outLen = outLen || 64;
  if (outLen < 1 || outLen > 64) throw new Error('BLAKE2b 输出长度须在 1~64 字节');
  var keyLen = keyBytes ? keyBytes.length : 0;
  if (keyLen > 64) throw new Error('BLAKE2b 密钥不超过 64 字节');
  var hl = new Uint32Array(8), hh = new Uint32Array(8), i;
  for (i = 0; i < 8; i++) { hl[i] = B2B_IV_LO[i]; hh[i] = B2B_IV_HI[i]; }
  hl[0] = (hl[0] ^ (0x01010000 ^ outLen ^ (keyLen << 8))) >>> 0;
  var bs = 128;
  var blocks = [];
  if (keyLen) { var kb = new Uint8Array(bs); kb.set(keyBytes); blocks.push(kb); }
  var nFull = Math.floor(input.length / bs);
  for (i = 0; i < nFull; i++) blocks.push(input.subarray(i * bs, (i + 1) * bs));
  var rem = input.length - nFull * bs;
  if (rem > 0) {
    var tail = new Uint8Array(bs);
    tail.set(input.subarray(nFull * bs));
    blocks.push(tail);
  } else if (blocks.length === 0) {
    blocks.push(new Uint8Array(bs));
  }
  var t = 0;
  for (i = 0; i < blocks.length; i++) {
    var isLast = (i === blocks.length - 1);
    var inc;
    if (i === 0 && keyLen) inc = bs;
    else if (isLast && rem > 0) inc = rem;
    else if (isLast && input.length === 0 && !keyLen) inc = 0;
    else inc = bs;
    t += inc;
    blake2bCompress(hl, hh, blocks[i], t, isLast);
  }
  var out = new Uint8Array(outLen), pos = 0;
  for (i = 0; i < 8 && pos < outLen; i++) {
    var lo = hl[i], hi = hh[i];
    var seq = [lo & 0xff, (lo >>> 8) & 0xff, (lo >>> 16) & 0xff, (lo >>> 24) & 0xff,
               hi & 0xff, (hi >>> 8) & 0xff, (hi >>> 16) & 0xff, (hi >>> 24) & 0xff];
    for (var j = 0; j < 8 && pos < outLen; j++) out[pos++] = seq[j];
  }
  return out;
}

/* ============================================================
* 2. RIPEMD-160（ISO/IEC 10118-3）
* ============================================================ */
var RMD_RL = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13];
var RMD_RR = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11];
var RMD_SL = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6];
var RMD_SR = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11];
function rmdF(j, x, y, z) {
if (j < 16) return (x ^ y ^ z) >>> 0;
if (j < 32) return ((x & y) | (~x & z)) >>> 0;
if (j < 48) return ((x | ~y) ^ z) >>> 0;
if (j < 64) return ((x & z) | (y & ~z)) >>> 0;
return (x ^ (y | ~z)) >>> 0;
}
function ripemd160Digest(input) {
var h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
var ml = input.length * 8;
var total = Math.ceil((input.length + 9) / 64) * 64;
var buf = new Uint8Array(total);
buf.set(input);
buf[input.length] = 0x80;
/* 注意：JS 的 >>> 会把移位数掩码成 mod 32，所以 x>>>32 等于 x>>>0（没移位）。
   超过 32 位的位移必须改用除法拆分高低 32 位。 */
var mlHi = Math.floor(ml / 4294967296);
buf[total - 8] = ml & 255; buf[total - 7] = (ml >>> 8) & 255;
buf[total - 6] = (ml >>> 16) & 255; buf[total - 5] = (ml >>> 24) & 255;
buf[total - 4] = mlHi & 255; buf[total - 3] = (mlHi >>> 8) & 255;
buf[total - 2] = (mlHi >>> 16) & 255; buf[total - 1] = (mlHi >>> 24) & 255;
var X = new Int32Array(16);
for (var o = 0; o < total; o += 64) {
for (var i = 0; i < 16; i++) X[i] = (buf[o + i * 4] | (buf[o + i * 4 + 1] << 8) | (buf[o + i * 4 + 2] << 16) | (buf[o + i * 4 + 3] << 24)) | 0;
var al = h[0], bl = h[1], cl = h[2], dl = h[3], el = h[4];
var ar = h[0], br = h[1], cr = h[2], dr = h[3], er = h[4];
for (var j = 0; j < 80; j++) {
var f = rmdF(j, bl, cl, dl);
var Kl = (j < 16) ? 0x00000000 : (j < 32) ? 0x5A827999 : (j < 48) ? 0x6ED9EBA1 : (j < 64) ? 0x8F1BBCDC : 0xA953FD4E;
var Kr = (j < 16) ? 0x50A28BE6 : (j < 32) ? 0x5C4DD124 : (j < 48) ? 0x6D703EF3 : (j < 64) ? 0x7A6D76E9 : 0x00000000;
var Tl = (rotl32((al + (f >>> 0) + (X[RMD_RL[j]] >>> 0) + Kl) >>> 0, RMD_SL[j]) + el) >>> 0;
al = el; el = dl; dl = rotl32(cl, 10) >>> 0; cl = bl; bl = Tl;
var fr = rmdF(79 - j, br, cr, dr);
var Tr = (rotl32((ar + (fr >>> 0) + (X[RMD_RR[j]] >>> 0) + Kr) >>> 0, RMD_SR[j]) + er) >>> 0;
ar = er; er = dr; dr = rotl32(cr, 10) >>> 0; cr = br; br = Tr;
}
var T = (h[1] + cl + dr) >>> 0;
h[1] = (h[2] + dl + er) >>> 0;
h[2] = (h[3] + el + ar) >>> 0;
h[3] = (h[4] + al + br) >>> 0;
h[4] = (h[0] + bl + cr) >>> 0;
h[0] = T;
}
var out = new Uint8Array(20);
for (var i = 0; i < 5; i++) { out[i * 4] = h[i] & 255; out[i * 4 + 1] = (h[i] >>> 8) & 255; out[i * 4 + 2] = (h[i] >>> 16) & 255; out[i * 4 + 3] = (h[i] >>> 24) & 255; }
return out;
}

/* ============================================================
* 3. 同步 HMAC-SHA256（复用主文件的 sha256Core）
* ============================================================ */
function sha256Bytes(input) { return sha256Core(input, SHA256_IV, 8); }
function hmacSha256(keyBytes, msg) {
var bs = 64;
var k = keyBytes;
if (k.length > bs) k = sha256Bytes(k);
var ik = new Uint8Array(bs), ok = new Uint8Array(bs);
ik.fill(0x36); ok.fill(0x5c);
for (var i = 0; i < k.length; i++) { ik[i] ^= k[i]; ok[i] ^= k[i]; }
return sha256Bytes(concatBytes(ok, sha256Bytes(concatBytes(ik, msg))));
}
function pbkdf2Sha256(password, salt, iters, dkLen) {
var hLen = 32;
var nBlocks = Math.ceil(dkLen / hLen);
var out = new Uint8Array(nBlocks * hLen);
for (var b = 1; b <= nBlocks; b++) {
var uBlock = concatBytes(salt, new Uint8Array([(b >>> 24) & 255, (b >>> 16) & 255, (b >>> 8) & 255, b & 255]));
var u = hmacSha256(password, uBlock);
var t = new Uint8Array(u);
for (var i = 1; i < iters; i++) {
u = hmacSha256(password, u);
for (var j = 0; j < hLen; j++) t[j] ^= u[j];
}
out.set(t, (b - 1) * hLen);
}
return out.subarray(0, dkLen);
}

/* ============================================================
* 4. HKDF（RFC 5869）
* ============================================================ */
function hkdfSha256(ikm, salt, info, length) {
if (!salt || salt.length === 0) salt = new Uint8Array(32);
var prk = hmacSha256(salt, ikm);
var out = new Uint8Array(length);
var t = new Uint8Array(0);
var pos = 0;
for (var i = 1; pos < length; i++) {
t = hmacSha256(prk, concatBytes(concatBytes(t, info || new Uint8Array(0)), new Uint8Array([i & 255])));
var take = Math.min(t.length, length - pos);
out.set(t.subarray(0, take), pos);
pos += take;
}
return out;
}

/* ============================================================
* 5. scrypt（RFC 7914）：PBKDF2 + Salsa20/8 + ROMix
* ============================================================ */
function salsaQuarter(x, a, b, c, d) {
x[b] = (x[b] ^ rotl32((x[a] + x[d]) >>> 0, 7)) >>> 0;
x[c] = (x[c] ^ rotl32((x[b] + x[a]) >>> 0, 9)) >>> 0;
x[d] = (x[d] ^ rotl32((x[c] + x[b]) >>> 0, 13)) >>> 0;
x[a] = (x[a] ^ rotl32((x[d] + x[c]) >>> 0, 18)) >>> 0;
}
function salsa20_8(block64) {
var x = new Uint32Array(16);
for (var i = 0; i < 16; i++) x[i] = (block64[i * 4] | (block64[i * 4 + 1] << 8) | (block64[i * 4 + 2] << 16) | (block64[i * 4 + 3] << 24)) >>> 0;
var orig = new Uint32Array(x);
for (var r = 0; r < 4; r++) {
salsaQuarter(x, 0, 4, 8, 12); salsaQuarter(x, 5, 9, 13, 1);
salsaQuarter(x, 10, 14, 2, 6); salsaQuarter(x, 15, 3, 7, 11);
salsaQuarter(x, 0, 1, 2, 3); salsaQuarter(x, 5, 6, 7, 4);
salsaQuarter(x, 10, 11, 8, 9); salsaQuarter(x, 15, 12, 13, 14);
}
var out = new Uint8Array(64);
for (var i = 0; i < 16; i++) {
var v = (x[i] + orig[i]) >>> 0;
out[i * 4] = v & 255; out[i * 4 + 1] = (v >>> 8) & 255; out[i * 4 + 2] = (v >>> 16) & 255; out[i * 4 + 3] = (v >>> 24) & 255;
}
return out;
}
function blockMix(B, r) {
var tmp = new Uint8Array(64);
var X = new Uint8Array(64);
X.set(B.subarray((2 * r - 1) * 64, 2 * r * 64));
var Y = new Uint8Array(128 * r);
for (var i = 0; i < 2 * r; i++) {
for (var j = 0; j < 64; j++) tmp[j] = X[j] ^ B[i * 64 + j];
X = salsa20_8(tmp);
Y.set(X, i * 64);
}
var out = new Uint8Array(128 * r);
for (var i = 0; i < r; i++) {
out.set(Y.subarray(i * 2 * 64, (i * 2 + 1) * 64), i * 64);
}
for (var i = 0; i < r; i++) {
out.set(Y.subarray((i * 2 + 1) * 64, (i * 2 + 2) * 64), (r + i) * 64);
}
return out;
}
function scryptROMix(B, r, N) {
var V = [];
var X = new Uint8Array(B);
for (var i = 0; i < N; i++) { V.push(new Uint8Array(X)); X = blockMix(X, r); }
for (var i = 0; i < N; i++) {
var off = (2 * r - 1) * 64;
var j = (X[off] | (X[off + 1] << 8) | (X[off + 2] << 16) | (X[off + 3] << 24)) >>> 0;
var jh = (X[off + 4] | (X[off + 5] << 8) | (X[off + 6] << 16) | (X[off + 7] << 24)) >>> 0;
var idx = ((jh % N) * 4294967296 + j) % N;
idx = idx % N;
var vj = V[idx];
for (var k = 0; k < X.length; k++) X[k] ^= vj[k];
X = blockMix(X, r);
}
return X;
}
function scryptDigest(password, salt, N, r, p, dkLen) {
if ((N & (N - 1)) !== 0) throw new Error('scrypt 的 N 必须是 2 的幂');
if (N < 2) throw new Error('scrypt 的 N 至少为 2');
if (r < 1 || p < 1) throw new Error('scrypt 的 r/p 至少为 1');
var B = pbkdf2Sha256(password, salt, 1, p * 128 * r);
for (var i = 0; i < p; i++) {
var chunk = B.subarray(i * 128 * r, (i + 1) * 128 * r);
var res = scryptROMix(chunk, r, N);
B.set(res, i * 128 * r);
}
return pbkdf2Sha256(password, B, 1, dkLen);
}

/* ============================================================
* 6. AES-GCM（GHASH 纯 JS + 主文件 AES）
* ============================================================ */
function gfMul(a, b) { /* a,b: Uint8Array(16)，GF(2^128) 乘法（GCM 位序） */
var Z = new Uint8Array(16), V = new Uint8Array(b);
for (var i = 0; i < 128; i++) {
var bit = (a[(i >> 3) | 0] >> (7 - (i & 7))) & 1;
if (bit) for (var j = 0; j < 16; j++) Z[j] ^= V[j];
var lsb = V[15] & 1;
var carry = lsb ? 0xE1 : 0;
for (var j = 15; j >= 0; j--) {
var nv = (V[j] >>> 1);
if (j > 0) nv |= (V[j - 1] & 1) << 7;
V[j] = nv;
}
V[0] ^= carry;
}
return Z;
}
function pad16(b) { var p = (16 - (b.length % 16)) % 16; return concatBytes(b, new Uint8Array(p)); }
function ghash(h, data) {
var y = new Uint8Array(16);
var n = Math.floor(data.length / 16);
for (var i = 0; i < n; i++) {
for (var j = 0; j < 16; j++) y[j] ^= data[i * 16 + j];
y = gfMul(y, h);
}
return y;
}
function gcmInc32(cb) {
var out = new Uint8Array(cb);
for (var i = 15; i >= 12; i--) { if (++out[i] !== 0) break; }
return out;
}
function aesGcmEncrypt(plain, keyBytes, nonce, aad) {
var bs = 16;
if (nonce.length !== 12) throw new Error('GCM 需要 12 字节 nonce');
var f = aesMakeBlockFn(keyBytes);
var H = f.enc(new Uint8Array(16));
var J0 = concatBytes(nonce, new Uint8Array([0, 0, 0, 1]));
var ct = new Uint8Array(plain.length);
var cb = gcmInc32(new Uint8Array(J0));
for (var o = 0; o < plain.length; o += bs) {
var ks = f.enc(cb);
var len = Math.min(bs, plain.length - o);
for (var i = 0; i < len; i++) ct[o + i] = plain[o + i] ^ ks[i];
cb = gcmInc32(cb);
}
var lenA = aad.length * 8, lenC = plain.length * 8;
function lenBlock(len) {
var b = new Uint8Array(8);
var v = BigInt(len);
for (var i = 0; i < 8; i++) b[i] = Number((v >> BigInt(56 - 8 * i)) & 0xffn);
return b;
}
/* GHASH 是链式运算（Y_i = (Y_{i-1} ^ X_i)·H），必须对
   AAD || 密文 || len(AAD) || len(密文) 一次性连续计算，不能分段算再异或 */
var s = ghash(H, concatBytes(concatBytes(pad16(aad), pad16(ct)),
concatBytes(lenBlock(lenA), lenBlock(lenC))));
var sFull = new Uint8Array(16);
sFull.set(s);
var ek = f.enc(J0);
var tag = new Uint8Array(16);
for (var i = 0; i < 16; i++) tag[i] = sFull[i] ^ ek[i];
return { ciphertext: ct, tag: tag };
}
function aesGcmDecrypt(ct, tag, keyBytes, nonce, aad) {
var bs = 16;
if (nonce.length !== 12) throw new Error('GCM 需要 12 字节 nonce');
var f = aesMakeBlockFn(keyBytes);
var H = f.enc(new Uint8Array(16));
var J0 = concatBytes(nonce, new Uint8Array([0, 0, 0, 1]));
function lenBlock(len) {
var b = new Uint8Array(8);
var v = BigInt(len);
for (var i = 0; i < 8; i++) b[i] = Number((v >> BigInt(56 - 8 * i)) & 0xffn);
return b;
}
var s = ghash(H, concatBytes(concatBytes(pad16(aad), pad16(ct)),
concatBytes(lenBlock(aad.length * 8), lenBlock(ct.length * 8))));
var sFull = new Uint8Array(16);
sFull.set(s);
var ek = f.enc(J0);
var expect = new Uint8Array(16);
for (var i = 0; i < 16; i++) expect[i] = sFull[i] ^ ek[i];
var diff = 0;
for (var i = 0; i < 16; i++) diff |= (expect[i] ^ tag[i]);
if (diff !== 0) throw new Error('GCM 认证失败：密文或附加数据被篡改，或密钥/nonce 不正确');
var pt = new Uint8Array(ct.length);
var cb = gcmInc32(new Uint8Array(J0));
for (var o = 0; o < ct.length; o += bs) {
var ks = f.enc(cb);
var len = Math.min(bs, ct.length - o);
for (var i = 0; i < len; i++) pt[o + i] = ct[o + i] ^ ks[i];
cb = gcmInc32(cb);
}
return pt;
}

/* ============================================================
* 7. ChaCha20 + Poly1305 → ChaCha20-Poly1305（RFC 8439）
* ============================================================ */
function chachaQuarter(x, a, b, c, d) {
x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl32((x[d] ^ x[a]) >>> 0, 16);
x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl32((x[b] ^ x[c]) >>> 0, 12);
x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl32((x[d] ^ x[a]) >>> 0, 8);
x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl32((x[b] ^ x[c]) >>> 0, 7);
}
function chacha20Block(key, counter, nonce) {
var x = new Uint32Array(16);
x[0] = 0x61707865; x[1] = 0x3320646e; x[2] = 0x79622d32; x[3] = 0x6b206574;
for (var i = 0; i < 8; i++) x[4 + i] = (key[i * 4] | (key[i * 4 + 1] << 8) | (key[i * 4 + 2] << 16) | (key[i * 4 + 3] << 24)) >>> 0;
x[12] = counter >>> 0;
for (var i = 0; i < 3; i++) x[13 + i] = (nonce[i * 4] | (nonce[i * 4 + 1] << 8) | (nonce[i * 4 + 2] << 16) | (nonce[i * 4 + 3] << 24)) >>> 0;
var w = new Uint32Array(x);
for (var r = 0; r < 10; r++) {
chachaQuarter(w, 0, 4, 8, 12); chachaQuarter(w, 1, 5, 9, 13);
chachaQuarter(w, 2, 6, 10, 14); chachaQuarter(w, 3, 7, 11, 15);
chachaQuarter(w, 0, 5, 10, 15); chachaQuarter(w, 1, 6, 11, 12);
chachaQuarter(w, 2, 7, 8, 13); chachaQuarter(w, 3, 4, 9, 14);
}
var out = new Uint8Array(64);
for (var i = 0; i < 16; i++) {
var v = (w[i] + x[i]) >>> 0;
out[i * 4] = v & 255; out[i * 4 + 1] = (v >>> 8) & 255; out[i * 4 + 2] = (v >>> 16) & 255; out[i * 4 + 3] = (v >>> 24) & 255;
}
return out;
}
function chacha20Stream(key, nonce, counter, len) {
var out = new Uint8Array(len);
var pos = 0, ctr = counter >>> 0;
while (pos < len) {
var ks = chacha20Block(key, ctr, nonce);
ctr = (ctr + 1) >>> 0;
var take = Math.min(64, len - pos);
out.set(ks.subarray(0, take), pos);
pos += take;
}
return out;
}
function poly1305Mac(msg, key) { /* key: 32 字节一次性密钥 */
var r = 0n, s = 0n;
for (var i = 0; i < 16; i++) r |= BigInt(key[i] & 0xff) << BigInt(8 * i);
r &= 0x0ffffffc0ffffffc0ffffffc0fffffffn;
for (var i = 0; i < 16; i++) s |= BigInt(key[16 + i] & 0xff) << BigInt(8 * i);
var p = (1n << 130n) - 5n;
var acc = 0n;
var n = Math.floor(msg.length / 16);
for (var i = 0; i < n; i++) {
var blk = 0n;
for (var j = 0; j < 16; j++) blk |= BigInt(msg[i * 16 + j] & 0xff) << BigInt(8 * j);
blk |= (1n << 128n);
acc = ((acc + blk) * r) % p;
}
var rem = msg.length - n * 16;
if (rem) {
var blk = 0n;
for (var j = 0; j < rem; j++) blk |= BigInt(msg[n * 16 + j] & 0xff) << BigInt(8 * j);
blk |= (1n << BigInt(8 * rem));
acc = ((acc + blk) * r) % p;
}
acc = (acc + s) & ((1n << 128n) - 1n);
var out = new Uint8Array(16);
for (var i = 0; i < 16; i++) out[i] = Number((acc >> BigInt(8 * i)) & 0xffn);
return out;
}
function chacha20Poly1305Encrypt(plain, keyBytes, nonce, aad) {
if (keyBytes.length !== 32) throw new Error('ChaCha20-Poly1305 需要 32 字节密钥');
if (nonce.length !== 12) throw new Error('ChaCha20-Poly1305 需要 12 字节 nonce');
var otk = chacha20Stream(keyBytes, nonce, 0, 32);
var ct = new Uint8Array(plain.length);
var ks = chacha20Stream(keyBytes, nonce, 1, plain.length);
for (var i = 0; i < plain.length; i++) ct[i] = plain[i] ^ ks[i];
function pad16(b) { var p = (16 - (b.length % 16)) % 16; return concatBytes(b, new Uint8Array(p)); }
var macData = concatBytes(pad16(aad), pad16(ct));
var lb = new Uint8Array(16);
function putLE(b, off, v) { for (var i = 0; i < 8; i++) b[off + i] = Number((v >> BigInt(8 * i)) & 0xffn); }
putLE(lb, 0, BigInt(aad.length));
putLE(lb, 8, BigInt(ct.length));
var tag = poly1305Mac(concatBytes(macData, lb), otk);
return { ciphertext: ct, tag: tag };
}
function chacha20Poly1305Decrypt(ct, tag, keyBytes, nonce, aad) {
if (keyBytes.length !== 32) throw new Error('ChaCha20-Poly1305 需要 32 字节密钥');
if (nonce.length !== 12) throw new Error('ChaCha20-Poly1305 需要 12 字节 nonce');
var otk = chacha20Stream(keyBytes, nonce, 0, 32);
function pad16(b) { var p = (16 - (b.length % 16)) % 16; return concatBytes(b, new Uint8Array(p)); }
var macData = concatBytes(pad16(aad), pad16(ct));
var lb = new Uint8Array(16);
function putLE(b, off, v) { for (var i = 0; i < 8; i++) b[off + i] = Number((v >> BigInt(8 * i)) & 0xffn); }
putLE(lb, 0, BigInt(aad.length));
putLE(lb, 8, BigInt(ct.length));
var expect = poly1305Mac(concatBytes(macData, lb), otk);
var diff = 0;
for (var i = 0; i < 16; i++) diff |= (expect[i] ^ tag[i]);
if (diff !== 0) throw new Error('ChaCha20-Poly1305 认证失败：密文或附加数据被篡改，或密钥/nonce 不正确');
var pt = new Uint8Array(ct.length);
var ks = chacha20Stream(keyBytes, nonce, 1, ct.length);
for (var i = 0; i < ct.length; i++) pt[i] = ct[i] ^ ks[i];
return pt;
}
/* ============================================================
* crypto-extra2.js 第四部分：TEA 族 / GOST Magma / 古典密码
* ============================================================ */

/* ============================================================
* 1. TEA / XTEA（64 位块、128 位密钥、32 轮 Feistel）
* ============================================================ */
var TEA_DELTA = 0x9E3779B9;
function teaEncBlock(block, k) {
var v0 = readU32BE(block, 0), v1 = readU32BE(block, 4);
var sum = 0;
for (var i = 0; i < 32; i++) {
sum = (sum + TEA_DELTA) >>> 0;
v0 = (v0 + ((((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >>> 5) + k[2])) >>> 0)) >>> 0;
v1 = (v1 + ((((v0 << 4) + k[1]) ^ (v0 + sum) ^ ((v0 >>> 5) + k[3])) >>> 0)) >>> 0;
}
var out = new Uint8Array(8);
writeU32BE(v0, out, 0); writeU32BE(v1, out, 4);
return out;
}
function teaDecBlock(block, k) {
var v0 = readU32BE(block, 0), v1 = readU32BE(block, 4);
var sum = (TEA_DELTA * 32) >>> 0;
for (var i = 0; i < 32; i++) {
v1 = (v1 - ((((v0 << 4) + k[1]) ^ (v0 + sum) ^ ((v0 >>> 5) + k[3])) >>> 0)) >>> 0;
v0 = (v0 - ((((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >>> 5) + k[2])) >>> 0)) >>> 0;
sum = (sum - TEA_DELTA) >>> 0;
}
var out = new Uint8Array(8);
writeU32BE(v0, out, 0); writeU32BE(v1, out, 4);
return out;
}
function xteaEncBlock(block, k) {
var v0 = readU32BE(block, 0), v1 = readU32BE(block, 4);
var sum = 0;
for (var i = 0; i < 32; i++) {
v0 = (v0 + (((((v1 << 4) ^ (v1 >>> 5)) + v1) >>> 0) ^ ((sum + k[sum & 3]) >>> 0))) >>> 0;
sum = (sum + TEA_DELTA) >>> 0;
v1 = (v1 + (((((v0 << 4) ^ (v0 >>> 5)) + v0) >>> 0) ^ ((sum + k[(sum >>> 11) & 3]) >>> 0))) >>> 0;
}
var out = new Uint8Array(8);
writeU32BE(v0, out, 0); writeU32BE(v1, out, 4);
return out;
}
function xteaDecBlock(block, k) {
var v0 = readU32BE(block, 0), v1 = readU32BE(block, 4);
var sum = (TEA_DELTA * 32) >>> 0;
for (var i = 0; i < 32; i++) {
v1 = (v1 - (((((v0 << 4) ^ (v0 >>> 5)) + v0) >>> 0) ^ ((sum + k[(sum >>> 11) & 3]) >>> 0))) >>> 0;
sum = (sum - TEA_DELTA) >>> 0;
v0 = (v0 - (((((v1 << 4) ^ (v1 >>> 5)) + v1) >>> 0) ^ ((sum + k[sum & 3]) >>> 0))) >>> 0;
}
var out = new Uint8Array(8);
writeU32BE(v0, out, 0); writeU32BE(v1, out, 4);
return out;
}
function teaKeyWords(keyBytes) {
var k = new Uint32Array(4);
for (var i = 0; i < 4; i++) k[i] = readU32BE(keyBytes, i * 4);
return k;
}
function teaMakeBlockFn(keyBytes) {
var k = teaKeyWords(keyBytes);
return { enc: function (b) { return teaEncBlock(b, k); }, dec: function (b) { return teaDecBlock(b, k); } };
}
function xteaMakeBlockFn(keyBytes) {
var k = teaKeyWords(keyBytes);
return { enc: function (b) { return xteaEncBlock(b, k); }, dec: function (b) { return xteaDecBlock(b, k); } };
}

/* ============================================================
* 2. XXTEA（Corrected Block TEA）—— 变长块，按 32 位字处理
* ============================================================ */
function xxteaEncryptWords(v, k) {
var n = v.length;
if (n < 2) return v.slice();
var rounds = 6 + Math.floor(52 / n);
var sum = 0;
var z = v[n - 1];
for (var r = 0; r < rounds; r++) {
sum = (sum + TEA_DELTA) >>> 0;
var e = (sum >>> 2) & 3;
for (var p = 0; p < n; p++) {
var y = v[(p + 1) % n];
var mx = (((((z >>> 5) ^ (y << 2)) >>> 0) + ((y >>> 3) ^ (z << 4))) >>> 0) ^ (((sum ^ y) >>> 0) + ((k[(p & 3) ^ e] ^ z) >>> 0) >>> 0);
v[p] = (v[p] + mx) >>> 0;
z = v[p];
}
}
return v;
}
function xxteaDecryptWords(v, k) {
var n = v.length;
if (n < 2) return v.slice();
var rounds = 6 + Math.floor(52 / n);
var sum = (rounds * TEA_DELTA) >>> 0;
var y = v[0];
for (var r = 0; r < rounds; r++) {
var e = (sum >>> 2) & 3;
for (var p = n - 1; p >= 0; p--) {
var z = v[(p - 1 + n) % n];
var mx = (((((z >>> 5) ^ (y << 2)) >>> 0) + ((y >>> 3) ^ (z << 4))) >>> 0) ^ (((sum ^ y) >>> 0) + ((k[(p & 3) ^ e] ^ z) >>> 0) >>> 0);
v[p] = (v[p] - mx) >>> 0;
y = v[p];
}
sum = (sum - TEA_DELTA) >>> 0;
}
return v;
}
function xxteaEncryptBytes(plain, keyBytes) {
var k = teaKeyWords(keyBytes);
var hdr = new Uint8Array(4);
hdr[0] = (plain.length >>> 24) & 255; hdr[1] = (plain.length >>> 16) & 255;
hdr[2] = (plain.length >>> 8) & 255; hdr[3] = plain.length & 255;
var framed = concatBytes(hdr, plain);
var padLen = (4 - (framed.length % 4)) % 4;
if (padLen) framed = concatBytes(framed, new Uint8Array(padLen));
var words = new Uint32Array(framed.length / 4);
for (var i = 0; i < words.length; i++) words[i] = readU32BE(framed, i * 4);
xxteaEncryptWords(words, k);
var out = new Uint8Array(framed.length);
for (var i = 0; i < words.length; i++) writeU32BE(words[i], out, i * 4);
return out;
}
function xxteaDecryptBytes(raw, keyBytes) {
var k = teaKeyWords(keyBytes);
if (raw.length === 0 || raw.length % 4 !== 0) throw new Error('XXTEA 密文长度必须是 4 字节的整数倍');
var words = new Uint32Array(raw.length / 4);
for (var i = 0; i < words.length; i++) words[i] = readU32BE(raw, i * 4);
xxteaDecryptWords(words, k);
var framed = new Uint8Array(raw.length);
for (var i = 0; i < words.length; i++) writeU32BE(words[i], framed, i * 4);
var len = ((framed[0] << 24) | (framed[1] << 16) | (framed[2] << 8) | framed[3]) >>> 0;
if (len > framed.length - 4) throw new Error('XXTEA 解密失败：长度字段异常（密钥错误或密文损坏）');
return framed.subarray(4, 4 + len);
}

/* ============================================================
* 3. GOST Magma（GOST R 34.12-2015 / RFC 8891，256 位密钥、64 位块）
* ============================================================ */
/* id-tc26-gost-28147-param-Z S-box（RFC 7836 附录 C），8 行 × 16 值 */
var MAGMA_SBOX = [
[12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
[6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
[11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
[12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
[7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
[5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
[8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
[1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2]
];
function magmaSubst(x) {
var out = 0;
for (var i = 0; i < 8; i++) {
var nib = (x >>> (4 * i)) & 0xF;      /* 第 i 行作用于从低位数起的第 i 个半字节 */
out |= (MAGMA_SBOX[i][nib] << (4 * i));
}
return out >>> 0;
}
/* 把 8 行 × 16 值的 S 盒预合成 4 张 256 项字节表。
 * 半字节 i（从低位数起）走 MAGMA_SBOX[i]，故
 *   字节3(bits 0-7)  = SBOX[1][高4] | SBOX[0][低4]
 *   字节2(bits 8-15) = SBOX[3][高4] | SBOX[2][低4]
 *   …… 依次到字节0 用 SBOX[7]/SBOX[6]。
 * ⚠ 与 GOST 28147 不同：Magma 的半字节序是【正】的（i=0 是最低半字节），
 *   而 GOST_SBOX 的字节序是反的；两者若混用不会报错，只会静默算错。
 * 合成后每个 F 只剩 4 次查表，去掉原来每轮 8 次二维数组解引用。 */
var MAGMA_T = [new Uint8Array(256), new Uint8Array(256), new Uint8Array(256), new Uint8Array(256)];
(function buildMagmaT() {
var i, b;
for (i = 0; i < 4; i++) {
var rowHi = MAGMA_SBOX[2 * i + 1], rowLo = MAGMA_SBOX[2 * i];
for (b = 0; b < 256; b++) {
MAGMA_T[3 - i][b] = ((rowHi[(b & 0xf0) >> 4] << 4) | rowLo[b & 0x0f]) & 0xff;
}
}
})();
function magmaF(k, x) {
var s = (k + x) >>> 0;
var v = ((MAGMA_T[0][(s >>> 24) & 0xff] << 24) |
(MAGMA_T[1][(s >>> 16) & 0xff] << 16) |
(MAGMA_T[2][(s >>> 8) & 0xff] << 8) |
MAGMA_T[3][s & 0xff]) >>> 0;
return (((v << 11) | (v >>> 21)) >>> 0);
}
/* 轮结构（与 GOST R 34.12-2015 标准实现一致）：
   状态 (a1, a0) = (高 32 位, 低 32 位)，G 函数作用于低半部分 a0。
   前 31 轮：(a1,a0) ← (a0, a1 ^ G(K_i, a0))       —— 交换
   第 32 轮：(a1,a0) ← (a1 ^ G(K_32, a0), a0)      —— 不交换
   解密结构相同，只是轮密钥顺序反过来。 */
function magmaEncBlock(block, K) {
var a1 = readU32BE(block, 0), a0 = readU32BE(block, 4);
for (var i = 0; i < 31; i++) {
var g = (a1 ^ magmaF(K[i], a0)) >>> 0;
a1 = a0; a0 = g;
}
a1 = (a1 ^ magmaF(K[31], a0)) >>> 0;
var out = new Uint8Array(8);
writeU32BE(a1, out, 0); writeU32BE(a0, out, 4);
return out;
}
function magmaDecBlock(block, K) {
var a1 = readU32BE(block, 0), a0 = readU32BE(block, 4);
for (var i = 31; i >= 1; i--) {
var g = (a1 ^ magmaF(K[i], a0)) >>> 0;
a1 = a0; a0 = g;
}
a1 = (a1 ^ magmaF(K[0], a0)) >>> 0;
var out = new Uint8Array(8);
writeU32BE(a1, out, 0); writeU32BE(a0, out, 4);
return out;
}
function magmaMakeBlockFn(keyBytes) {
/* 密钥按大端解析为 8 个 u32；轮密钥顺序 K1..K8 三次，再逆序 K8..K1 */
var base = new Uint32Array(8);
for (var i = 0; i < 8; i++) base[i] = readU32BE(keyBytes, i * 4);
var K = new Uint32Array(32);
for (var i = 0; i < 24; i++) K[i] = base[i % 8];
for (var i = 0; i < 8; i++) K[24 + i] = base[7 - i];
return { enc: function (b) { return magmaEncBlock(b, K); }, dec: function (b) { return magmaDecBlock(b, K); } };
}

/* ============================================================
* 4. 古典密码（面向文本）
* ============================================================ */
function isLetter(ch) { return /[A-Za-z]/.test(ch); }
function shiftChar(ch, n) {
if (/[A-Z]/.test(ch)) return String.fromCharCode(((ch.charCodeAt(0) - 65 + n) % 26 + 26) % 26 + 65);
if (/[a-z]/.test(ch)) return String.fromCharCode(((ch.charCodeAt(0) - 97 + n) % 26 + 26) % 26 + 97);
return ch;
}
function vigenereEnc(text, key) {
if (!key) throw new Error('请填写密钥词（参数栏，纯字母）');
var k = key.replace(/[^A-Za-z]/g, '').toUpperCase();
if (!k) throw new Error('密钥词必须包含至少一个字母');
var ki = 0, out = '';
for (var i = 0; i < text.length; i++) {
var ch = text[i];
if (isLetter(ch)) { out += shiftChar(ch, k.charCodeAt(ki % k.length) - 65); ki++; }
else out += ch;
}
return out;
}
function vigenereDec(text, key) {
var k = key.replace(/[^A-Za-z]/g, '').toUpperCase();
if (!k) throw new Error('密钥词必须包含至少一个字母');
var ki = 0, out = '';
for (var i = 0; i < text.length; i++) {
var ch = text[i];
if (isLetter(ch)) { out += shiftChar(ch, -(k.charCodeAt(ki % k.length) - 65)); ki++; }
else out += ch;
}
return out;
}
function atbashMap(s) {
var out = '';
for (var i = 0; i < s.length; i++) {
var c = s[i];
if (/[A-Z]/.test(c)) out += String.fromCharCode(90 - (c.charCodeAt(0) - 65));
else if (/[a-z]/.test(c)) out += String.fromCharCode(122 - (c.charCodeAt(0) - 97));
else out += c;
}
return out;
}
function gcd(a, b) { while (b) { var t = a % b; a = b; b = t; } return a; }
function modInv(a, m) {
a = ((a % m) + m) % m;
for (var x = 1; x < m; x++) if ((a * x) % m === 1) return x;
return 0;
}
function parseAffine(param) {
var parts = String(param || '5,8').split(/[\s,]+/).filter(Boolean);
var a = parseInt(parts[0], 10), b = parseInt(parts[1], 10);
if (isNaN(a)) a = 5; if (isNaN(b)) b = 8;
if (gcd(a, 26) !== 1) throw new Error('仿射密码要求 a 与 26 互素（可用 1,3,5,7,9,11,15,17,19,21,23,25）');
return { a: a, b: b };
}
function affineEnc(text, param) {
var p = parseAffine(param), out = '';
for (var i = 0; i < text.length; i++) {
var c = text[i];
if (/[A-Z]/.test(c)) out += String.fromCharCode(((p.a * (c.charCodeAt(0) - 65) + p.b) % 26) + 65);
else if (/[a-z]/.test(c)) out += String.fromCharCode(((p.a * (c.charCodeAt(0) - 97) + p.b) % 26) + 97);
else out += c;
}
return out;
}
function affineDec(text, param) {
var p = parseAffine(param), inv = modInv(p.a, 26), out = '';
for (var i = 0; i < text.length; i++) {
var c = text[i];
if (/[A-Z]/.test(c)) out += String.fromCharCode(((inv * ((c.charCodeAt(0) - 65) - p.b)) % 26 + 26) % 26 + 65);
else if (/[a-z]/.test(c)) out += String.fromCharCode(((inv * ((c.charCodeAt(0) - 97) - p.b)) % 26 + 26) % 26 + 97);
else out += c;
}
return out;
}
function railFenceEnc(text, railsParam) {
var rails = parseInt(railsParam, 10);
if (isNaN(rails) || rails < 2) rails = 3;
if (rails >= text.length) rails = 2;
var rows = [];
for (var i = 0; i < rails; i++) rows.push('');
var r = 0, dir = 1;
for (var i = 0; i < text.length; i++) {
rows[r] += text[i];
if (r === 0) dir = 1;
else if (r === rails - 1) dir = -1;
r += dir;
}
return rows.join('');
}
function railFenceDec(text, railsParam) {
var rails = parseInt(railsParam, 10);
if (isNaN(rails) || rails < 2) rails = 3;
if (rails >= text.length) rails = 2;
var lens = new Array(rails).fill(0);
var r = 0, dir = 1;
for (var i = 0; i < text.length; i++) {
lens[r]++;
if (r === 0) dir = 1;
else if (r === rails - 1) dir = -1;
r += dir;
}
var rows = [], pos = 0;
for (var i = 0; i < rails; i++) { rows.push(text.substr(pos, lens[i])); pos += lens[i]; }
var out = '', idx = new Array(rails).fill(0);
r = 0; dir = 1;
for (var i = 0; i < text.length; i++) {
out += rows[r][idx[r]++];
if (r === 0) dir = 1;
else if (r === rails - 1) dir = -1;
r += dir;
}
return out;
}
function playfairSquare(key) {
var k = String(key || 'PLAYFAIR').toUpperCase().replace(/[^A-Z]/g, '').replace(/J/g, 'I');
var seen = {}, sq = '';
for (var i = 0; i < k.length; i++) if (!seen[k[i]]) { seen[k[i]] = 1; sq += k[i]; }
for (var c = 65; c <= 90; c++) {
var ch = String.fromCharCode(c);
if (ch === 'J') continue;
if (!seen[ch]) { seen[ch] = 1; sq += ch; }
}
return sq;
}
function playfairPairs(text) {
var t = text.toUpperCase().replace(/[^A-Z]/g, '').replace(/J/g, 'I');
var pairs = [], i = 0;
while (i < t.length) {
var a = t[i], b = t[i + 1];
if (!b) { pairs.push(a + 'X'); break; }
if (a === b) { pairs.push(a + 'X'); i++; }
else { pairs.push(a + b); i += 2; }
}
return pairs;
}
function playfairEnc(text, key) {
var sq = playfairSquare(key);
var pos = {};
for (var i = 0; i < 25; i++) pos[sq[i]] = [Math.floor(i / 5), i % 5];
var out = '';
playfairPairs(text).forEach(function (pair) {
var p1 = pos[pair[0]], p2 = pos[pair[1]];
if (p1[0] === p2[0]) out += sq[p1[0] * 5 + (p1[1] + 1) % 5] + sq[p2[0] * 5 + (p2[1] + 1) % 5];
else if (p1[1] === p2[1]) out += sq[((p1[0] + 1) % 5) * 5 + p1[1]] + sq[((p2[0] + 1) % 5) * 5 + p2[1]];
else out += sq[p1[0] * 5 + p2[1]] + sq[p2[0] * 5 + p1[1]];
});
return out;
}
function playfairDec(text, key) {
var sq = playfairSquare(key);
var pos = {};
for (var i = 0; i < 25; i++) pos[sq[i]] = [Math.floor(i / 5), i % 5];
var t = text.toUpperCase().replace(/[^A-Z]/g, '');
var out = '';
for (var i = 0; i < t.length; i += 2) {
var p1 = pos[t[i]], p2 = pos[t[i + 1]];
if (!p1 || !p2) break;
if (p1[0] === p2[0]) out += sq[p1[0] * 5 + (p1[1] + 4) % 5] + sq[p2[0] * 5 + (p2[1] + 4) % 5];
else if (p1[1] === p2[1]) out += sq[((p1[0] + 4) % 5) * 5 + p1[1]] + sq[((p2[0] + 4) % 5) * 5 + p2[1]];
else out += sq[p1[0] * 5 + p2[1]] + sq[p2[0] * 5 + p1[1]];
}
return out;
}
var BACON_MAP = (function () {
var m = {};
for (var i = 0; i < 26; i++) {
var code = '';
for (var b = 4; b >= 0; b--) code += ((i >> b) & 1) ? 'b' : 'a';
m[code] = String.fromCharCode(65 + i);
}
return m;
})();
function baconEnc(text) {
var out = '';
for (var i = 0; i < text.length; i++) {
var c = text[i].toUpperCase();
if (/[A-Z]/.test(c)) {
var idx = c.charCodeAt(0) - 65, code = '';
for (var b = 4; b >= 0; b--) code += ((idx >> b) & 1) ? 'b' : 'a';
out += code + ' ';
} else if (c === ' ') out += ' ';
}
return out.trim();
}
function baconDec(text) {
var clean = text.toLowerCase().replace(/[^ab]/g, '');
var out = '';
for (var i = 0; i + 5 <= clean.length; i += 5) {
var ch = BACON_MAP[clean.substr(i, 5)];
if (ch) out += ch;
}
return out;
}

/* ============================================================
* 5. 注册到 ALGOS
* ============================================================ */
if (typeof regSym === 'function') {
regSym({ id: 'tea', name: 'TEA', group: '对称加密',
keyLabel: '密钥（任意字符串，SHA-256 派生 16 字节）',
blockSize: 8, keyLen: 16, makeBlockFn: teaMakeBlockFn,
info: 'Tiny Encryption Algorithm，64 位块、128 位密钥、32 轮 Feistel。教学用途为主，已知存在相关密钥攻击，不宜用于新系统。' });
regSym({ id: 'xtea', name: 'XTEA', group: '对称加密',
keyLabel: '密钥（任意字符串，SHA-256 派生 16 字节）',
blockSize: 8, keyLen: 16, makeBlockFn: xteaMakeBlockFn,
info: 'eXtended TEA，修正了 TEA 的密钥调度弱点。64 位块、128 位密钥。' });
regSym({ id: 'magma', name: 'GOST Magma（RFC 8891）', group: '对称加密',
keyLabel: '密钥（任意字符串，SHA-256 派生 32 字节）',
blockSize: 8, keyLen: 32, makeBlockFn: magmaMakeBlockFn,
info: '俄罗斯国家标准 GOST R 34.12-2015 的 64 位分组密码（原 GOST 28147-89），256 位密钥、32 轮 Feistel，S 盒固定为 param-Z。' });
}
reg({ id: 'xxtea', name: 'XXTEA', group: '对称加密', key: true, param: false,
keyLabel: '密钥（任意字符串，SHA-256 派生 16 字节）',
info: 'Corrected Block TEA，变长块（按 32 位字处理），128 位密钥。适合短数据，不适合长消息。',
enc: async function (b, k, p, fmt) {
var kb = await deriveKeyBytes(k, 16);
return bytesOut(xxteaEncryptBytes(b, kb), fmt);
},
dec: async function (s, k, p, fmt) {
var kb = await deriveKeyBytes(k, 16);
return xxteaDecryptBytes(bytesIn(s, fmt), kb);
} });

reg({ id: 'vigenere', name: '维吉尼亚密码', group: '古典密码', key: false, param: true,
paramLabel: '密钥词（字母）',
info: '多表替换密码：用密钥词逐字母移位。只处理字母，其余字符原样保留。',
enc: function (b, k, p, fmt) { return vigenereEnc(bytesToStr(b), p); },
dec: function (s, k, p, fmt) { return vigenereDec(s, p); } });
reg({ id: 'atbash', name: 'Atbash 密码', group: '古典密码', key: false, param: false,
info: '单表替换：字母表反转（A↔Z，a↔z）。希伯来字母表起源。',
enc: function (b, k, p, fmt) { return atbashMap(bytesToStr(b)); },
dec: function (s, k, p, fmt) { return atbashMap(s); } });
reg({ id: 'affine', name: '仿射密码', group: '古典密码', key: false, param: true,
paramLabel: '参数 a,b（默认 5,8）',
info: 'E(x) = a·x + b (mod 26)，要求 a 与 26 互素。',
enc: function (b, k, p, fmt) { return affineEnc(bytesToStr(b), p); },
dec: function (s, k, p, fmt) { return affineDec(s, p); } });
reg({ id: 'railfence', name: '栅栏密码', group: '古典密码', key: false, param: true,
paramLabel: '栏数（默认 3）',
info: 'Rail Fence 置换密码：按之字形写入多行再按行读出。只改变顺序，不改变字符。',
enc: function (b, k, p, fmt) { return railFenceEnc(bytesToStr(b), p); },
dec: function (s, k, p, fmt) { return railFenceDec(s, p); } });
reg({ id: 'playfair', name: 'Playfair 密码', group: '古典密码', key: false, param: true,
paramLabel: '密钥词（默认 PLAYFAIR）',
info: '双字母替换密码，使用 5×5 方阵（I/J 合并）。输出为大写字母串。',
enc: function (b, k, p, fmt) { return playfairEnc(bytesToStr(b), p); },
dec: function (s, k, p, fmt) { return playfairDec(s, p); } });
reg({ id: 'bacon', name: '培根密码', group: '古典密码', key: false, param: false,
info: 'Bacon 隐写密码：每个字母编码为 5 个 a/b。',
enc: function (b, k, p, fmt) { return baconEnc(bytesToStr(b)); },
dec: function (s, k, p, fmt) { return baconDec(s); } });

function aeadSplit(s, fmt, nonceLen, tagLen) {
var raw = bytesIn(s, fmt);
if (raw.length < nonceLen + tagLen) throw new Error('密文长度不足（需要 nonce + 密文 + 认证标签）');
return { nonce: raw.subarray(0, nonceLen), tag: raw.subarray(raw.length - tagLen),
ct: raw.subarray(nonceLen, raw.length - tagLen) };
}
reg({ id: 'aes-gcm', name: 'AES-GCM（认证加密）', group: '对称加密', key: true, param: true,
keyLabel: '密钥（任意字符串，SHA-256 派生 32 字节）',
paramLabel: '附加数据 AAD（可选，任意字符串）',
info: 'AEAD 认证加密：AES-256 的 GCM 模式，同时提供机密性与完整性。输出 = nonce(12) || 密文 || 标签(16)。解密时标签校验失败会直接报错。',
enc: async function (b, k, p, fmt) {
var kb = await deriveKeyBytes(k, 32);
var nonce = crypto.getRandomValues(new Uint8Array(12));
var aad = p ? strToBytes(p) : new Uint8Array(0);
var r = aesGcmEncrypt(b, kb, nonce, aad);
return bytesOut(concatBytes(concatBytes(nonce, r.ciphertext), r.tag), fmt);
},
dec: async function (s, k, p, fmt) {
var kb = await deriveKeyBytes(k, 32);
var aad = p ? strToBytes(p) : new Uint8Array(0);
var sp = aeadSplit(s, fmt, 12, 16);
return aesGcmDecrypt(sp.ct, sp.tag, kb, sp.nonce, aad);
} });
reg({ id: 'chacha20-poly1305', name: 'ChaCha20-Poly1305（认证加密）', group: '对称加密', key: true, param: true,
keyLabel: '密钥（任意字符串，SHA-256 派生 32 字节）',
paramLabel: '附加数据 AAD（可选，任意字符串）',
info: 'RFC 8439 AEAD：ChaCha20 流密码 + Poly1305 认证。输出 = nonce(12) || 密文 || 标签(16)。在无 AES 硬件加速的设备上通常快于 AES-GCM。',
enc: async function (b, k, p, fmt) {
var kb = await deriveKeyBytes(k, 32);
var nonce = crypto.getRandomValues(new Uint8Array(12));
var aad = p ? strToBytes(p) : new Uint8Array(0);
var r = chacha20Poly1305Encrypt(b, kb, nonce, aad);
return bytesOut(concatBytes(concatBytes(nonce, r.ciphertext), r.tag), fmt);
},
dec: async function (s, k, p, fmt) {
var kb = await deriveKeyBytes(k, 32);
var aad = p ? strToBytes(p) : new Uint8Array(0);
var sp = aeadSplit(s, fmt, 12, 16);
return chacha20Poly1305Decrypt(sp.ct, sp.tag, kb, sp.nonce, aad);
} });

if (typeof oneway === 'function') {
oneway({ id: 'blake3', name: 'BLAKE3-256', group: '单向哈希', key: true, param: true,
paramLabel: '模式：留空=普通哈希；key=32字节Hex密钥；dk=派生上下文字符串',
info: 'BLAKE3：比 BLAKE2 更快，原生支持密钥模式与密钥派生。已与官方参考实现逐条比对通过（22 组，含 1024/2048/4096 等多块树哈希边界）。',
enc: function (b, k, p, fmt) {
  var o = {};
  if (p && p.indexOf('key=') === 0) {
    var kb = hexToBytes(p.slice(4).trim());
    o = { key: kb };
  } else if (p && p.indexOf('dk=') === 0) {
    o = { context: p.slice(3) };
  } else if (k && k.length === 64 && /^[0-9a-fA-F]{64}$/.test(k)) {
    o = { key: hexToBytes(k) };
  }
  return bytesOut(blake3Hash(b, o), fmt);
} });

oneway({ id: 'blake2b', name: 'BLAKE2b-512', group: '单向哈希', key: false, param: true,
paramLabel: '输出字节数（1~64，默认 64）',
info: 'BLAKE2b（RFC 7693），比 SHA-2 更快且安全性更强，默认输出 64 字节。',
enc: function (b, k, p, fmt) {
var n = parseInt(p, 10);
if (isNaN(n) || n < 1 || n > 64) n = 64;
return bytesOut(blake2bDigest(b, n, null), fmt);
} });
oneway({ id: 'ripemd160', name: 'RIPEMD-160', group: '单向哈希', key: false, param: false,
info: '160 位摘要，比特币地址生成中使用（与 SHA-256 串联）。',
enc: function (b, k, p, fmt) { return bytesOut(ripemd160Digest(b), fmt); } });
}

reg({ id: 'hmac', name: 'HMAC 消息认证码', group: '单向哈希', key: true, param: true,
keyLabel: '密钥（任意字符串）',
paramLabel: '哈希算法（SHA-256/SHA-512/SHA-1，默认 SHA-256）',
info: '密钥化哈希，用于验证消息完整性与真实性。输入为待认证消息。',
enc: async function (b, k, p, fmt) {
var name = String(p || 'SHA-256').toUpperCase().replace('SHA', 'SHA-');
if (name !== 'SHA-1' && name !== 'SHA-256' && name !== 'SHA-384' && name !== 'SHA-512') name = 'SHA-256';
var keyBytes = strToBytes(k || '');
var mk = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: name }, false, ['sign']);
var sig = await crypto.subtle.sign('HMAC', mk, b);
return bytesOut(new Uint8Array(sig), fmt);
},
dec: function () { throw new Error('HMAC 是单向认证码，无法解密；请直接比对两次计算结果'); } });
reg({ id: 'pbkdf2', name: 'PBKDF2 密钥派生', group: '单向哈希', key: true, param: true,
keyLabel: '盐值 salt（任意字符串）',
paramLabel: '迭代次数（默认 100000）',
info: '口令派生密钥（PBKDF2-HMAC-SHA256）。输入栏填口令，输出 32 字节派生密钥。',
enc: async function (b, k, p, fmt) {
var iters = parseInt(p, 10);
if (isNaN(iters) || iters < 1) iters = 100000;
if (iters > 2000000) throw new Error('迭代次数过大（上限 200 万），会导致浏览器卡死');
var salt = strToBytes(k || '');
var mk = await crypto.subtle.importKey('raw', b, 'PBKDF2', false, ['deriveBits']);
var bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: salt, iterations: iters, hash: 'SHA-256' }, mk, 256);
return bytesOut(new Uint8Array(bits), fmt);
},
dec: function () { throw new Error('PBKDF2 是单向派生函数，无法解密'); } });
reg({ id: 'hkdf', name: 'HKDF 密钥派生', group: '单向哈希', key: true, param: true,
keyLabel: 'info（可选，应用标识）',
paramLabel: '输出字节数（默认 32）',
info: 'HKDF-SHA256（RFC 5869）。输入栏填原始密钥材料 IKM，输出派生的密钥。',
enc: function (b, k, p, fmt) {
if (!b.length) throw new Error('请在输入栏填写原始密钥材料 IKM');
var len = parseInt(p, 10);
if (isNaN(len) || len < 1 || len > 8160) len = 32;
var info = strToBytes(k || '');
/* 用已与 RFC 5869 参考实现验证过的纯 JS HKDF，不依赖浏览器算法支持 */
return bytesOut(hkdfSha256(b, new Uint8Array(0), info, len), fmt);
},
dec: function () { throw new Error('HKDF 是单向派生函数，无法解密'); } });
reg({ id: 'scrypt', name: 'scrypt 口令派生', group: '单向哈希', key: true, param: true,
keyLabel: '盐值 salt（任意字符串）',
paramLabel: 'N,r,p（默认 16384,8,1，N 须为 2 的幂）',
info: '抗 ASIC 的内存困难型口令派生函数（RFC 7914）。N 越大越慢越安全；为免卡死，浏览器上限 N=32768。',
enc: async function (b, k, p, fmt) {
var parts = String(p || '16384,8,1').split(/[\s,]+/).filter(Boolean);
var N = parseInt(parts[0], 10), r = parseInt(parts[1], 10), pr = parseInt(parts[2], 10);
if (isNaN(N)) N = 16384; if (isNaN(r)) r = 8; if (isNaN(pr)) pr = 1;
if (N > 32768) throw new Error('N 上限为 32768（更大的值会长时间阻塞浏览器）');
var salt = strToBytes(k || '');
if (!b.length) throw new Error('请在输入栏填写口令');
return bytesOut(scryptDigest(b, salt, N, r, pr, 32), fmt);
},
dec: function () { throw new Error('scrypt 是单向派生函数，无法解密'); } });
/* ============================================================
* crypto-extra4.js 第一部分：
*   Streebog-256/512 · Kuznyechik · SHAKE/cSHAKE/KMAC/KangarooTwelve
*   常量表由 gostcrypto（Python 权威实现）源码自动导出
* ============================================================ */

var STREEBOG_T = null;
function streebogGetT() {
if (STREEBOG_T) return STREEBOG_T;
STREEBOG_T = [];
for (var i = 0; i < 8; i++) {
var row = new Array(256);
for (var j = 0; j < 256; j++) row[j] = BigInt('0x' + STREEBOG_T_HEX[i][j]);
STREEBOG_T.push(row);
}
return STREEBOG_T;
}
var STREEBOG_T_LO = null, STREEBOG_T_HI = null;
function streebogGetTHL() {
  if (STREEBOG_T_LO) return { lo: STREEBOG_T_LO, hi: STREEBOG_T_HI };
  var T = streebogGetT();
  STREEBOG_T_LO = []; STREEBOG_T_HI = [];
  for (var r = 0; r < T.length; r++) {
    var lo = new Uint32Array(256), hi = new Uint32Array(256);
    for (var j = 0; j < 256; j++) {
      lo[j] = Number(T[r][j] & 0xffffffffn) >>> 0;
      hi[j] = Number((T[r][j] >> 32n) & 0xffffffffn) >>> 0;
    }
    STREEBOG_T_LO.push(lo); STREEBOG_T_HI.push(hi);
  }
  return { lo: STREEBOG_T_LO, hi: STREEBOG_T_HI };
}
/* T 表拆成 lo/hi 两张【扁平】Uint32Array 后缓存到模块级：
 * ⚠ 原先 (1) 每次 LPS 都调 streebogGetTHL() 并新建返回对象；
 *      (2) 用 TL[r][idx] 二维数组解引用。
 *   每块约 25 次 LPS × 64 次查表，这两项开销都很可观。
 *   扁平表 TFLAT[r*256+idx] 只需一次乘加。 */
var SB_TL = null, SB_TH = null;
function streebogInitT() {
  if (SB_TL) return;
  var T = streebogGetT();
  SB_TL = new Uint32Array(2048); SB_TH = new Uint32Array(2048);
  for (var r = 0; r < T.length; r++) {
    for (var j = 0; j < 256; j++) {
      SB_TL[r * 256 + j] = Number(T[r][j] & 0xffffffffn) >>> 0;
      SB_TH[r * 256 + j] = Number((T[r][j] >> 32n) & 0xffffffffn) >>> 0;
    }
  }
}
/* 输出缓冲：同一块内存上挂 Uint8 与 Uint32 两个视图。
 * LPS 的 64 位结果是【小端】，小端机器上直接写 out32[k*2]/[k*2+1] 即可，
 * 省掉 8 次逐字节拆分。字节序用一次运行时检测确认。 */
var SB_ENDIAN_LITTLE = (function () {
  var b = new ArrayBuffer(4);
  new Uint32Array(b)[0] = 1;
  return new Uint8Array(b)[0] === 1;
})();
var sbBuf = new ArrayBuffer(64);
var sbOut8 = new Uint8Array(sbBuf), sbOut32 = new Uint32Array(sbBuf);
/* S ∘ P ∘ L：data 排成 8×8 矩阵，第 k 列 8 个字节分别查 T[0..7] 再异或。
 * 内层 8 次查表完全展开。out 为调用方提供的 64 字节缓冲，不新分配。 */
function streebogLpsInto(data, out) {
  streebogInitT();
  var k, vl, vh, b0, b1, b2, b3, b4, b5, b6, b7;
  if (SB_ENDIAN_LITTLE && out.buffer) {
    var o32 = new Uint32Array(out.buffer, out.byteOffset, 16);
    for (k = 0; k < 8; k++) {
      b0 = data[k]; b1 = data[k + 8]; b2 = data[k + 16]; b3 = data[k + 24];
      b4 = data[k + 32]; b5 = data[k + 40]; b6 = data[k + 48]; b7 = data[k + 56];
      vl = (SB_TL[b0] ^ SB_TL[256 + b1] ^ SB_TL[512 + b2] ^ SB_TL[768 + b3] ^
            SB_TL[1024 + b4] ^ SB_TL[1280 + b5] ^ SB_TL[1536 + b6] ^ SB_TL[1792 + b7]) >>> 0;
      vh = (SB_TH[b0] ^ SB_TH[256 + b1] ^ SB_TH[512 + b2] ^ SB_TH[768 + b3] ^
            SB_TH[1024 + b4] ^ SB_TH[1280 + b5] ^ SB_TH[1536 + b6] ^ SB_TH[1792 + b7]) >>> 0;
      o32[k * 2] = vl; o32[k * 2 + 1] = vh;
    }
    return;
  }
  for (k = 0; k < 8; k++) {
    b0 = data[k]; b1 = data[k + 8]; b2 = data[k + 16]; b3 = data[k + 24];
    b4 = data[k + 32]; b5 = data[k + 40]; b6 = data[k + 48]; b7 = data[k + 56];
    vl = (SB_TL[b0] ^ SB_TL[256 + b1] ^ SB_TL[512 + b2] ^ SB_TL[768 + b3] ^
          SB_TL[1024 + b4] ^ SB_TL[1280 + b5] ^ SB_TL[1536 + b6] ^ SB_TL[1792 + b7]) >>> 0;
    vh = (SB_TH[b0] ^ SB_TH[256 + b1] ^ SB_TH[512 + b2] ^ SB_TH[768 + b3] ^
          SB_TH[1024 + b4] ^ SB_TH[1280 + b5] ^ SB_TH[1536 + b6] ^ SB_TH[1792 + b7]) >>> 0;
    out[k*8]   = vl & 0xff;         out[k*8+1] = (vl >>> 8) & 0xff;
    out[k*8+2] = (vl >>> 16) & 0xff; out[k*8+3] = (vl >>> 24) & 0xff;
    out[k*8+4] = vh & 0xff;         out[k*8+5] = (vh >>> 8) & 0xff;
    out[k*8+6] = (vh >>> 16) & 0xff; out[k*8+7] = (vh >>> 24) & 0xff;
  }
}
/* 保留旧签名供外部/测试参考，内部走 Into 版本 */
function streebogLPS(data) {
  var out = new Uint8Array(64);
  streebogLpsInto(data, out);
  return out;
}
var sbA = new Uint8Array(64), sbB = new Uint8Array(64), sbC = new Uint8Array(64), sbD = new Uint8Array(64);
function streebogXorInto(a, b, out) { for (var i = 0; i < 64; i++) out[i] = a[i] ^ b[i]; return out; }
function streebogXor(a, b) { return streebogXorInto(a, b, new Uint8Array(64)); }
function streebogAdd512(a, b) {
  var out = new Uint8Array(64), carry = 0, i;
  for (i = 0; i < 64; i++) { carry = a[i] + b[i] + (carry >> 8); out[i] = carry & 255; }
  return out;
}
/* E(k, m)：12 轮，每轮 internal = LPS(internal) ^ LPS(k ^ C[i])，并更新 k。
 * 全部在预分配的 sbA/sbB/sbC/sbD 上原地打转，不再每轮新建 4 个 64 字节数组。 */
function streebogEInto(k, data, out) {
  var i, j;
  for (j = 0; j < 64; j++) sbA[j] = k[j] ^ data[j];       /* internal = k ^ m */
  for (i = 0; i < 12; i++) {
    streebogLpsInto(sbA, sbB);                             /* LPS(internal) */
    var c = STREEBOG_C[i];
    for (j = 0; j < 64; j++) sbC[j] = k[j] ^ c[j];
    streebogLpsInto(sbC, sbD);                             /* 新的 k */
    for (j = 0; j < 64; j++) sbA[j] = sbB[j] ^ sbD[j];
    for (j = 0; j < 64; j++) k[j] = sbD[j];
  }
  out.set(sbA);
}
function streebogE(k, data) {
  var kk = new Uint8Array(k), out = new Uint8Array(64);
  streebogEInto(kk, data, out);
  return out;
}
function streebogGInto(h, n, data, out) {
  var j;
  for (j = 0; j < 64; j++) sbA[j] = n[j] ^ h[j];
  streebogLpsInto(sbA, sbC);                               /* k = LPS(n ^ h) */
  streebogEInto(sbC, data, sbB);                           /* E(k, m) */
  for (j = 0; j < 64; j++) out[j] = sbB[j] ^ h[j] ^ data[j];
}
function streebogG(h, n, data) {
  var out = new Uint8Array(64);
  streebogGInto(h, n, data, out);
  return out;
}
function streebogDigest(input, outLen) {
  outLen = outLen || 64;
  var h = new Uint8Array(64);
  if (outLen === 32) h.fill(0x01);    /* Streebog-256 初始值全 1 */
  var n = new Uint8Array(64), sigma = new Uint8Array(64);
  var V512 = new Uint8Array(64); V512[1] = 0x02;   /* 小端 512 */
  var V0 = new Uint8Array(64);
  var hNew = new Uint8Array(64), nNew = new Uint8Array(64), sgNew = new Uint8Array(64);
  var nFull = Math.floor(input.length / 64), i;
  for (i = 0; i < nFull; i++) {
    var block = input.subarray(i * 64, (i + 1) * 64);
    streebogGInto(h, n, block, hNew); h.set(hNew);
    streebogAddInto(n, V512, nNew); n.set(nNew);
    streebogAddInto(sigma, block, sgNew); sigma.set(sgNew);
  }
  var rem = input.length - nFull * 64;
  var last = new Uint8Array(64);
  last.set(input.subarray(nFull * 64));
  last[rem] = 0x01;
  streebogGInto(h, n, last, hNew); h.set(hNew);
  var bitLen = rem * 8, lenBlock = new Uint8Array(64);
  lenBlock[0] = bitLen & 255; lenBlock[1] = (bitLen >>> 8) & 255;
  streebogAddInto(n, lenBlock, nNew); n.set(nNew);
  streebogAddInto(sigma, last, sgNew); sigma.set(sgNew);
  streebogGInto(h, V0, n, hNew); h.set(hNew);
  streebogGInto(h, V0, sigma, hNew); h.set(hNew);
  return h.subarray(64 - outLen);
}
/* 原地版 512 位加法：out = a + b（可 out===a 吗？不能，逐字节进位需读旧 a，
 * 故约定 out 必须是独立缓冲） */
function streebogAddInto(a, b, out) {
  var carry = 0, i;
  for (i = 0; i < 64; i++) { carry = a[i] + b[i] + (carry >> 8); out[i] = carry & 255; }
}

function kuzXor(a, b) {
var out = new Uint8Array(16);
for (var i = 0; i < 16; i++) out[i] = a[i] ^ b[i];
return out;
}
function kuzS(data) {
var out = new Uint8Array(16);
for (var i = 0; i < 16; i++) out[i] = KUZ_SBOX[data[i]];
return out;
}
function kuzSInv(data) {
var out = new Uint8Array(16);
for (var i = 0; i < 16; i++) out[i] = KUZ_SBOX_INV[data[i]];
return out;
}
function kuzR(data) {
var res = new Uint8Array(16);
var a0 = 0;
for (var i = 0; i < 16; i++) {
res[i] = data[(i + 15) % 16];       /* data[i-1]，负索引即末尾 */
a0 ^= KUZ_GF[i][res[i]];
}
res[0] = a0;
return res;
}
function kuzRReverse(data) {
var res = new Uint8Array(16);
var a15 = 0;
for (var i = 15; i >= 0; i--) {
res[(i + 15) % 16] = data[i];       /* res[i-1] = data[i] */
a15 ^= KUZ_GF[i][data[i]];
}
res[15] = a15;
return res;
}
function kuzL(data) {
var res = new Uint8Array(data);
for (var i = 0; i < 16; i++) res = kuzR(res);
return res;
}
function kuzLInv(data) {
var res = new Uint8Array(data);
for (var i = 0; i < 16; i++) res = kuzRReverse(res);
return res;
}
/* L / L⁻¹ 都是 GF(2)^128 上的线性变换，可拆成「16 个单字节基向量」的异或。
 * 预先用【旧的、已验证的】kuzL / kuzLInv 生成两张表，每项是 4 个 32 位字，
 * 于是 L(v) 只需 16×4 次异或，不再逐轮分配数组。
 * 表由旧实现自身生成，故与旧行为严格等价（已逐块比对）。 */
var KUZ_LT = null, KUZ_LIT = null;
function kuzBuildLT() {
if (KUZ_LT) return;
KUZ_LT = []; KUZ_LIT = [];
var i, x, j;
for (i = 0; i < 16; i++) {
var ta = new Uint32Array(256 * 4), tb = new Uint32Array(256 * 4);
for (x = 0; x < 256; x++) {
var v = new Uint8Array(16); v[i] = x;
var la = kuzL(v), lb = kuzLInv(v);
for (j = 0; j < 4; j++) {
ta[x * 4 + j] = ((la[j*4] << 24) | (la[j*4+1] << 16) | (la[j*4+2] << 8) | la[j*4+3]) >>> 0;
tb[x * 4 + j] = ((lb[j*4] << 24) | (lb[j*4+1] << 16) | (lb[j*4+2] << 8) | lb[j*4+3]) >>> 0;
}
}
KUZ_LT.push(ta); KUZ_LIT.push(tb);
}
}
/* 字节数组 → 4 个 32 位字 / 反向 */
function kuzGet32(b, o) { return ((b[o] << 24) | (b[o+1] << 16) | (b[o+2] << 8) | b[o+3]) >>> 0; }
function kuzPut32(out, o, v) {
out[o] = (v >>> 24) & 0xff; out[o+1] = (v >>> 16) & 0xff; out[o+2] = (v >>> 8) & 0xff; out[o+3] = v & 0xff;
}
function kuzLFast(src, out) {
kuzBuildLT();
var i, w0 = 0, w1 = 0, w2 = 0, w3 = 0;
for (i = 0; i < 16; i++) {
var t = KUZ_LT[i], b = src[i] * 4;
w0 ^= t[b]; w1 ^= t[b+1]; w2 ^= t[b+2]; w3 ^= t[b+3];
}
kuzPut32(out, 0, w0); kuzPut32(out, 4, w1); kuzPut32(out, 8, w2); kuzPut32(out, 12, w3);
return out;
}
function kuzLInvFast(src, out) {
kuzBuildLT();
var i, w0 = 0, w1 = 0, w2 = 0, w3 = 0;
for (i = 0; i < 16; i++) {
var t = KUZ_LIT[i], b = src[i] * 4;
w0 ^= t[b]; w1 ^= t[b+1]; w2 ^= t[b+2]; w3 ^= t[b+3];
}
kuzPut32(out, 0, w0); kuzPut32(out, 4, w1); kuzPut32(out, 8, w2); kuzPut32(out, 12, w3);
return out;
}
/* 轮常数 C[i] = L(0…0,i)，与密钥无关 —— 原先每做一次密钥调度都重算 32 次 L，
 * 而每次 L 又是 16 轮 R。提到模块级只算一次。 */
var KUZ_C = null;
function kuzConstants() {
if (KUZ_C) return KUZ_C;
kuzBuildLT();
KUZ_C = [];
var i, internal = new Uint8Array(16), out = new Uint8Array(16);
for (i = 1; i <= 32; i++) {
internal.fill(0); internal[15] = i;
kuzLFast(internal, out);
KUZ_C.push(new Uint8Array(out));
}
return KUZ_C;
}
function kuzKeySchedule(keyBytes) {
var C = kuzConstants();
var k1 = new Uint8Array(keyBytes.subarray(0, 16));
var k2 = new Uint8Array(keyBytes.subarray(16, 32));
var iter = [new Uint8Array(k1), new Uint8Array(k2)];
var tmpX = new Uint8Array(16), tmpS = new Uint8Array(16), tmpL = new Uint8Array(16);
for (var i = 0; i < 4; i++) {
for (var j = 0; j < 8; j++) {
var c = C[i * 8 + j], q;
for (q = 0; q < 16; q++) { tmpX[q] = k1[q] ^ c[q]; tmpS[q] = KUZ_SBOX[tmpX[q]]; }
kuzLFast(tmpS, tmpL);
var nk1 = new Uint8Array(16);
for (q = 0; q < 16; q++) nk1[q] = tmpL[q] ^ k2[q];
k2 = new Uint8Array(k1);
k1 = nk1;
}
iter.push(new Uint8Array(k1));
iter.push(new Uint8Array(k2));
}
return iter;
}
/* S∘L 预合成表：KUZ_SLT[q][x] = LT[q][SBOX[x]]。
 * 加密一轮是 s ← L(S(K[i] ⊕ s))；L 在 GF(2) 上线性，可拆成 16 个基向量异或，
 * 于是整轮压成「16 次查表 + 4 路异或」，省掉中间的 S 盒步骤与 t 缓冲写入。
 * ⚠ 解密侧是 S⁻¹∘L⁻¹（非线性在后），无法这样合成，故只加速加密。 */
var KUZ_SLT = null;
function kuzBuildSLT() {
if (KUZ_SLT) return KUZ_SLT;
kuzBuildLT();
KUZ_SLT = [];
for (var q = 0; q < 16; q++) {
var lt = KUZ_LT[q], a = new Uint32Array(256 * 4);
for (var x = 0; x < 256; x++) {
var o = KUZ_SBOX[x] * 4;
a[x * 4] = lt[o]; a[x * 4 + 1] = lt[o + 1]; a[x * 4 + 2] = lt[o + 2]; a[x * 4 + 3] = lt[o + 3];
}
KUZ_SLT.push(a);
}
return KUZ_SLT;
}
function kuzMakeBlockFn(keyBytes) {
if (keyBytes.length !== 32) throw new Error('Kuznyechik 需要 32 字节密钥');
var K = kuzKeySchedule(keyBytes);
var SLT = kuzBuildSLT();
var s = new Uint8Array(16), t = new Uint8Array(16);
return {
enc: function (b) {
var i, q;
for (q = 0; q < 16; q++) s[q] = b[q];
for (i = 0; i < 9; i++) {
var Ki = K[i], w0 = 0, w1 = 0, w2 = 0, w3 = 0, tt, x;
for (q = 0; q < 16; q++) { tt = SLT[q]; x = (Ki[q] ^ s[q]) * 4; w0 ^= tt[x]; w1 ^= tt[x + 1]; w2 ^= tt[x + 2]; w3 ^= tt[x + 3]; }
kuzPut32(s, 0, w0); kuzPut32(s, 4, w1); kuzPut32(s, 8, w2); kuzPut32(s, 12, w3);
}
var out = new Uint8Array(16);
for (q = 0; q < 16; q++) out[q] = K[9][q] ^ s[q];
return out;
},
dec: function (b) {
var i, q;
for (q = 0; q < 16; q++) s[q] = K[9][q] ^ b[q];
for (i = 8; i >= 0; i--) {
kuzLInvFast(s, t);
/* 原来每轮都 new Uint8Array(16) 再 s.set(out)：9 次分配 + 9 次 16 字节拷贝/块。
   直接写回 s 即可 —— kuzLInvFast 读 s 写 t，无别名冲突。 */
for (q = 0; q < 16; q++) s[q] = K[i][q] ^ KUZ_SBOX_INV[t[q]];
}
return new Uint8Array(s);   /* 仍需拷贝：s 是复用缓冲，下次调用会被覆盖 */
}
};
}

/* ============================================================
* Keccak 家族扩展：SHAKE / cSHAKE / KMAC / KangarooTwelve
* 复用主文件的 keccakF
* ============================================================ */
/* keccakStateToBytes / keccakAbsorb / keccakF 由主文件提供（hi/lo 32 位实现）。
   这里曾有一份基于 BigInt 的重复定义，因加载顺序在后会把新实现覆盖掉，已移除。 */

function shakeDigest(input, outLen, rateBytes) {
var A = kecStateNew();
keccakAbsorb(A, input, rateBytes);
var lanes = rateBytes / 8;
var out = new Uint8Array(outLen);
var pos = 0;
while (pos < outLen) {
var chunk = keccakStateToBytes(A, lanes);
var take = Math.min(chunk.length, outLen - pos);
out.set(chunk.subarray(0, take), pos);
pos += take;
if (pos < outLen) keccakF(A);
}
return out;
}
function shake128Digest(input, outLen) { return shakeDigest(input, outLen || 32, 168); }
function shake256Digest(input, outLen) { return shakeDigest(input, outLen || 32, 136); }

/* NIST SP 800-185 的 cSHAKE：前缀 = encode_string(N) || encode_string(S) || 00 pad 到 rate */
/* NIST SP 800-185 的 bytepad(X, rate) = left_encode(rate) || X || 补零到 rate 的整数倍。
   开头的 left_encode(rate) 极易遗漏，漏了整个 cSHAKE/KMAC 结果就全错。
   另注意 encode_string(b"") = left_encode(0) || b"" = 0x01 0x00，也不能省略。 */
function cshakeBytePad(x, rateBytes) {
var toPad = concatBytes(leftEncode(rateBytes), x);
var npad = (rateBytes - (toPad.length % rateBytes)) % rateBytes;
return concatBytes(toPad, new Uint8Array(npad));
}
function cshakePadPrefix(n, s, rateBytes) {
var enc = function (b) { return concatBytes(leftEncode(b.length * 8), b); };
return cshakeBytePad(concatBytes(enc(n || new Uint8Array(0)), enc(s || new Uint8Array(0))), rateBytes);
}
function cshakeDigest(input, outLen, n, s, rateBytes) {
var A = kecStateNew();
var prefix = cshakePadPrefix(n, s, rateBytes);
/* 前缀整块吸收（不带 pad 字节，因为已补齐到 rate 整数倍） */
var lanes = rateBytes / 8;
for (var b = 0; b < prefix.length / rateBytes; b++) {
for (var i = 0; i < lanes; i++) kecXorLane(A, i, prefix, b * rateBytes + i * 8);
keccakF(A);
}
keccakAbsorb(A, input, rateBytes, 0x04);
var out = new Uint8Array(outLen);
var pos = 0;
while (pos < outLen) {
var chunk = keccakStateToBytes(A, lanes);
var take = Math.min(chunk.length, outLen - pos);
out.set(chunk.subarray(0, take), pos);
pos += take;
if (pos < outLen) keccakF(A);
}
return out;
}
function leftEncode(x) {
/* NIST SP 800-185 left_encode：输出长度字节 || 大端字节 */
if (x === 0) return new Uint8Array([1, 0]);
var bytes = [];
var v = x;
while (v > 0) { bytes.unshift(v & 255); v = Math.floor(v / 256); }
return concatBytes(new Uint8Array([bytes.length]), new Uint8Array(bytes));
}
function cshake128Digest(input, outLen, n, s) { return cshakeDigest(input, outLen || 32, n, s, 168); }
function cshake256Digest(input, outLen, n, s) { return cshakeDigest(input, outLen || 32, n, s, 136); }

/* KMAC = cSHAKE(key || right_encode(0) || input || right_encode(L·8), L, "KMAC", S) */
/* right_encode(x) = 值的大端字节 || 长度字节。
   注意 right_encode(0) 是 0x00 || 0x01（值和长度都要输出），
   这和 left_encode(0) = 0x01 || 0x00（长度在前）不同，别混用。 */
function rightEncode(x) {
if (x === 0) return new Uint8Array([0x00, 0x01]);
var bytes = [];
var v = x;
while (v > 0) { bytes.unshift(v & 255); v = Math.floor(v / 256); }
return concatBytes(new Uint8Array(bytes), new Uint8Array([bytes.length]));
}
/* KMAC = cSHAKE(bytepad(encode_str(K), rate) || X || right_encode(L·8), L, "KMAC", S) */
function kmacDigest(key, input, outLen, s, rateBytes, name) {
var n = strToBytes(name);
var bytepadded = cshakeBytePad(concatBytes(leftEncode(key.length * 8), key), rateBytes);
var data = concatBytes(concatBytes(bytepadded, input), rightEncode(outLen * 8));
return cshakeDigest(data, outLen, n, s || new Uint8Array(0), rateBytes);
}
function kmac128Digest(key, input, outLen, s) { return kmacDigest(key, input, outLen || 32, s, 168, 'KMAC'); }
function kmac256Digest(key, input, outLen, s) { return kmacDigest(key, input, outLen || 32, s, 136, 'KMAC'); }

/* ---------------- CMAC（NIST SP 800-38B，基于主文件 AES） ---------------- */
function cmacAes(keyBytes, msg) {
var f = aesMakeBlockFn(keyBytes);
var bs = 16;
var L = f.enc(new Uint8Array(bs));
function dbl(b) {
var out = new Uint8Array(bs);
var carry = 0;
for (var i = bs - 1; i >= 0; i--) {
var c = (b[i] << 1) & 0xff;
out[i] = c | carry;
carry = (b[i] >> 7) & 1;
}
if (carry) out[bs - 1] ^= 0x87;
return out;
}
var K1 = dbl(L);
var K2 = dbl(K1);
var nBlocks = Math.ceil(msg.length / bs);
var lastComplete = (msg.length > 0 && msg.length % bs === 0);
var blocks = lastComplete ? nBlocks : Math.max(1, nBlocks);
var x = new Uint8Array(bs);
for (var i = 0; i < blocks; i++) {
var block = new Uint8Array(bs);
var off = i * bs;
if (i === blocks - 1) {
var rem = msg.length - off;
if (lastComplete) {
block.set(msg.subarray(off, off + bs));
for (var j = 0; j < bs; j++) block[j] ^= K1[j];
} else {
block.set(msg.subarray(off));
block[rem] = 0x80;
for (var j = 0; j < bs; j++) block[j] ^= K2[j];
}
} else {
block.set(msg.subarray(off, off + bs));
}
var y = new Uint8Array(bs);
for (var j = 0; j < bs; j++) y[j] = x[j] ^ block[j];
x = f.enc(y);
}
return x;
}


/* ============================================================
* 注册：Streebog / SHAKE / KMAC / CMAC
* ============================================================ */
if (typeof oneway === 'function') {
oneway({ id: 'streebog256', name: 'Streebog-256', group: '单向哈希', key: false, param: false,
info: '俄罗斯国家标准哈希 GOST R 34.11-2012，256 位摘要。常量表由 gostcrypto 权威实现导出。',
enc: function (b, k, p, fmt) { return bytesOut(streebogDigest(b, 32), fmt); } });
oneway({ id: 'streebog512', name: 'Streebog-512', group: '单向哈希', key: false, param: false,
info: '俄罗斯国家标准哈希 GOST R 34.11-2012，512 位摘要。',
enc: function (b, k, p, fmt) { return bytesOut(streebogDigest(b, 64), fmt); } });
oneway({ id: 'shake128', name: 'SHAKE128（可扩展输出）', group: '单向哈希', key: false, param: true,
paramLabel: '输出字节数（默认 32）',
info: 'SHA-3 家族的可扩展输出函数（XOF），可输出任意长度。',
enc: function (b, k, p, fmt) {
var n = parseInt(p, 10); if (isNaN(n) || n < 1 || n > 4096) n = 32;
return bytesOut(shake128Digest(b, n), fmt);
} });
oneway({ id: 'shake256', name: 'SHAKE256（可扩展输出）', group: '单向哈希', key: false, param: true,
paramLabel: '输出字节数（默认 32）',
info: 'SHA-3 家族的可扩展输出函数（XOF），强度高于 SHAKE128。',
enc: function (b, k, p, fmt) {
var n = parseInt(p, 10); if (isNaN(n) || n < 1 || n > 4096) n = 32;
return bytesOut(shake256Digest(b, n), fmt);
} });
oneway({ id: 'cshake128', name: 'cSHAKE128（可定制）', group: '单向哈希', key: true, keyOptional: true, param: true,
keyLabel: '定制串 S（可选）', paramLabel: '输出字节数（默认 32）',
info: 'NIST SP 800-185 的可定制 XOF。输入栏填消息，密钥栏填定制串 S，参数栏填输出字节数。',
enc: function (b, k, p, fmt) {
var n = parseInt(p, 10); if (isNaN(n) || n < 1 || n > 4096) n = 32;
return bytesOut(cshake128Digest(b, n, new Uint8Array(0), strToBytes(k || '')), fmt);
} });
oneway({ id: 'cshake256', name: 'cSHAKE256（可定制）', group: '单向哈希', key: true, keyOptional: true, param: true,
keyLabel: '定制串 S（可选）', paramLabel: '输出字节数（默认 32）',
info: 'NIST SP 800-185 的可定制 XOF，强度高于 cSHAKE128。',
enc: function (b, k, p, fmt) {
var n = parseInt(p, 10); if (isNaN(n) || n < 1 || n > 4096) n = 32;
return bytesOut(cshake256Digest(b, n, new Uint8Array(0), strToBytes(k || '')), fmt);
} });
oneway({ id: 'cmac', name: 'CMAC-AES 消息认证码', group: '单向哈希', key: true, param: false,
keyLabel: '密钥（任意字符串，SHA-256 派生 32 字节）',
info: '基于分组密码的 MAC（NIST SP 800-38B），适合只有 AES 硬件加速的场景。输入栏填消息。',
enc: async function (b, k, p, fmt) {
var kb = await deriveKeyBytes(k, 32);
return bytesOut(cmacAes(kb, b), fmt);
},
dec: function () { throw new Error('CMAC 是单向认证码，无法解密；请直接比对两次计算结果'); } });
oneway({ id: 'kmac128', name: 'KMAC128', group: '单向哈希', key: true, param: true,
keyLabel: '密钥（至少 16 字节）',
paramLabel: '输出字节数（默认 32）',
info: 'NIST SP 800-185 的 Keccak MAC，带密钥与定制串，比 HMAC 更适合作为 KDF。输入栏填消息。',
enc: function (b, k, p, fmt) {
var n = parseInt(p, 10); if (isNaN(n) || n < 8 || n > 4096) n = 32;
var kb = strToBytes(k || '');
if (kb.length < 16) throw new Error('KMAC128 的密钥至少 16 字节');
return bytesOut(kmac128Digest(kb, b, n, new Uint8Array(0)), fmt);
},
dec: function () { throw new Error('KMAC 是单向认证码，无法解密'); } });
oneway({ id: 'kmac256', name: 'KMAC256', group: '单向哈希', key: true, param: true,
keyLabel: '密钥（至少 16 字节）',
paramLabel: '输出字节数（默认 32）',
info: 'NIST SP 800-185 的 Keccak MAC，强度高于 KMAC128。输入栏填消息。',
enc: function (b, k, p, fmt) {
var n = parseInt(p, 10); if (isNaN(n) || n < 8 || n > 4096) n = 32;
var kb = strToBytes(k || '');
if (kb.length < 16) throw new Error('KMAC256 的密钥至少 16 字节');
return bytesOut(kmac256Digest(kb, b, n, new Uint8Array(0)), fmt);
},
dec: function () { throw new Error('KMAC 是单向认证码，无法解密'); } });
}
/* ============================================================
* Serpent（AES 决赛算法）
* S-box 采用 bitslice 布尔函数形式，逻辑直接翻译自 pyserpent
* （标准参考实现），避免手工查表出错；已用 pyserpent 生成的
* 随机向量 + NESSIE 官方向量双重验证。
*
* 注意字节序：本实现沿用参考实现的小端字序约定，与
* BouncyCastle / pyserpent 一致（NESSIE 向量的字节是反着写的）。
* ============================================================ */

var SERPENT_SBOX = [_sbox0, _sbox1, _sbox2, _sbox3, _sbox4, _sbox5, _sbox6, _sbox7];
var SERPENT_INVBOX = [_inbox0, _inbox1, _inbox2, _inbox3, _inbox4, _inbox5, _inbox6, _inbox7];
/* 无分配版（由 _sboxN / _inboxN 自动派生）：每块 32 次 S 盒调用不再产生数组 */
var SERPENT_SBOX_INTO = [_sbox0Into, _sbox1Into, _sbox2Into, _sbox3Into, _sbox4Into, _sbox5Into, _sbox6Into, _sbox7Into];
var SERPENT_INVBOX_INTO = [_inbox0Into, _inbox1Into, _inbox2Into, _inbox3Into, _inbox4Into, _inbox5Into, _inbox6Into, _inbox7Into];
/* 加解密共用的 4 字暂存区。JS 单线程且此处无递归/重入，复用是安全的。 */
var _srpTmp = new Uint32Array(4);

function serpentLinear(x0, x1, x2, x3) {
x0 = rotl32(x0, 13);
x2 = rotl32(x2, 3);
x3 = (x3 ^ x2 ^ ((x0 << 3) >>> 0)) >>> 0;
x1 = (x1 ^ x0 ^ x2) >>> 0;
x3 = rotl32(x3, 7);
x1 = rotl32(x1, 1);
x0 = (x0 ^ x1 ^ x3) >>> 0;
x2 = (x2 ^ x3 ^ ((x1 << 7) >>> 0)) >>> 0;
x0 = rotl32(x0, 5);
x2 = rotl32(x2, 22);
return [x0 >>> 0, x1 >>> 0, x2 >>> 0, x3 >>> 0];
}
function serpentLinearInv(x0, x1, x2, x3) {
x2 = rotr32(x2, 22);
x0 = rotr32(x0, 5);
x2 = (x2 ^ x3 ^ ((x1 << 7) >>> 0)) >>> 0;
x0 = (x0 ^ x1 ^ x3) >>> 0;
x3 = rotr32(x3, 7);
x1 = rotr32(x1, 1);
x3 = (x3 ^ x2 ^ ((x0 << 3) >>> 0)) >>> 0;
x1 = (x1 ^ x0 ^ x2) >>> 0;
x2 = rotr32(x2, 3);
x0 = rotr32(x0, 13);
return [x0 >>> 0, x1 >>> 0, x2 >>> 0, x3 >>> 0];
}
/* 线性变换的无分配版：与 serpentLinear 逐行一致，只是写入 o 而非返回数组 */
function serpentLinearInto(x0, x1, x2, x3, o) {
x0 = rotl32(x0, 13);
x2 = rotl32(x2, 3);
x3 = (x3 ^ x2 ^ ((x0 << 3) >>> 0)) >>> 0;
x1 = (x1 ^ x0 ^ x2) >>> 0;
x3 = rotl32(x3, 7);
x1 = rotl32(x1, 1);
x0 = (x0 ^ x1 ^ x3) >>> 0;
x2 = (x2 ^ x3 ^ ((x1 << 7) >>> 0)) >>> 0;
x0 = rotl32(x0, 5);
x2 = rotl32(x2, 22);
o[0] = x0 >>> 0; o[1] = x1 >>> 0; o[2] = x2 >>> 0; o[3] = x3 >>> 0;
}
function serpentLinearInvInto(x0, x1, x2, x3, o) {
x2 = rotr32(x2, 22);
x0 = rotr32(x0, 5);
x2 = (x2 ^ x3 ^ ((x1 << 7) >>> 0)) >>> 0;
x0 = (x0 ^ x1 ^ x3) >>> 0;
x3 = rotr32(x3, 7);
x1 = rotr32(x1, 1);
x3 = (x3 ^ x2 ^ ((x0 << 3) >>> 0)) >>> 0;
x1 = (x1 ^ x0 ^ x2) >>> 0;
x2 = rotr32(x2, 3);
x0 = rotr32(x0, 13);
o[0] = x0 >>> 0; o[1] = x1 >>> 0; o[2] = x2 >>> 0; o[3] = x3 >>> 0;
}
function serpentKeySchedule(keyBytes) {
var lk = new Uint32Array(140);
var nWords = Math.floor((keyBytes.length * 8 + 31) / 32);
for (var i = 0; i < nWords; i++) lk[i] = readU32LE(keyBytes, i * 4);
for (var i = nWords; i < 8; i++) lk[i] = 0;
if (keyBytes.length * 8 < 256) {
var idx = Math.floor((keyBytes.length * 8) / 32);
var bit = 1 << ((keyBytes.length * 8) % 32);
lk[idx] = ((lk[idx] & (bit - 1)) | bit) >>> 0;
}
var prev = new Uint32Array(140);
prev.set(lk.subarray(0, 8));
for (var i = 0; i < 132; i++) {
var v = (prev[i] ^ prev[i + 3] ^ prev[i + 5] ^ prev[i + 7] ^ 0x9e3779b9 ^ i) >>> 0;
prev[i + 8] = rotl32(v, 11);
}
for (var j = 0; j < 33; j++) {
var a = prev[4 * j + 8], b = prev[4 * j + 9], c = prev[4 * j + 10], d = prev[4 * j + 11];
/* JS 的 % 对负数保留负号（Python 返回正），必须归一化 */
var r = SERPENT_SBOX[((3 - j) % 8 + 8) % 8](a, b, c, d);
prev[4 * j + 8] = r[0]; prev[4 * j + 9] = r[1];
prev[4 * j + 10] = r[2]; prev[4 * j + 11] = r[3];
}
return prev;
}
function serpentEncBlock(block, K) {
var a = readU32LE(block, 0), b = readU32LE(block, 4), c = readU32LE(block, 8), d = readU32LE(block, 12);
var o = _srpTmp;
for (var i = 0; i < 32; i++) {
a = (a ^ K[4 * i + 8]) >>> 0;
b = (b ^ K[4 * i + 9]) >>> 0;
c = (c ^ K[4 * i + 10]) >>> 0;
d = (d ^ K[4 * i + 11]) >>> 0;
SERPENT_SBOX_INTO[i & 7](a, b, c, d, o);
a = o[0]; b = o[1]; c = o[2]; d = o[3];
if (i < 31) {
serpentLinearInto(a, b, c, d, o);
a = o[0]; b = o[1]; c = o[2]; d = o[3];
}
}
a = (a ^ K[4 * 32 + 8]) >>> 0;
b = (b ^ K[4 * 32 + 9]) >>> 0;
c = (c ^ K[4 * 32 + 10]) >>> 0;
d = (d ^ K[4 * 32 + 11]) >>> 0;
var out = new Uint8Array(16);
writeU32LE(a, out, 0); writeU32LE(b, out, 4); writeU32LE(c, out, 8); writeU32LE(d, out, 12);
return out;
}
function serpentDecBlock(block, K) {
var a = readU32LE(block, 0), b = readU32LE(block, 4), c = readU32LE(block, 8), d = readU32LE(block, 12);
var o = _srpTmp;
a = (a ^ K[4 * 32 + 8]) >>> 0;
b = (b ^ K[4 * 32 + 9]) >>> 0;
c = (c ^ K[4 * 32 + 10]) >>> 0;
d = (d ^ K[4 * 32 + 11]) >>> 0;
for (var i = 31; i >= 0; i--) {
if (i < 31) {
serpentLinearInvInto(a, b, c, d, o);
a = o[0]; b = o[1]; c = o[2]; d = o[3];
}
SERPENT_INVBOX_INTO[i & 7](a, b, c, d, o);
a = o[0]; b = o[1]; c = o[2]; d = o[3];
a = (a ^ K[4 * i + 8]) >>> 0;
b = (b ^ K[4 * i + 9]) >>> 0;
c = (c ^ K[4 * i + 10]) >>> 0;
d = (d ^ K[4 * i + 11]) >>> 0;
}
var out = new Uint8Array(16);
writeU32LE(a, out, 0); writeU32LE(b, out, 4); writeU32LE(c, out, 8); writeU32LE(d, out, 12);
return out;
}
function serpentMakeBlockFn(keyBytes) {
if (keyBytes.length > 32) throw new Error('Serpent 密钥最多 32 字节');
var K = serpentKeySchedule(keyBytes);
return { enc: function (b) { return serpentEncBlock(b, K); }, dec: function (b) { return serpentDecBlock(b, K); } };
}

/* ============================================================
* AES-CCM（NIST SP 800-38C）：CBC-MAC + CTR
* ============================================================ */
function ccmFormatB0(nonce, mlen, alen, tagLen, q) {
var b0 = new Uint8Array(16);
b0[0] = 64 * ((alen > 0) ? 1 : 0) + 8 * Math.floor((tagLen - 2) / 2) + (q - 1);
for (var i = 1; i < 1 + (15 - q); i++) b0[i] = nonce[i - 1];
var rem = 15 - q;   /* b0[15-q+1 .. 15] 放 mlen（大端，q 字节） */
var v = mlen;
for (var i = 15; i > rem; i--) { b0[i] = v & 255; v = Math.floor(v / 256); }
return b0;
}
function ccmFormatA(aad) {
var len = aad.length;
var pre;
if (len < 0xFF00) { pre = new Uint8Array(2); pre[0] = (len >>> 8) & 255; pre[1] = len & 255; }
else {
pre = new Uint8Array(6);
pre[0] = 0xFF; pre[1] = 0xFE;
for (var i = 2; i < 6; i++) pre[i] = (len >>> (8 * (5 - i))) & 255;
}
var pad = (16 - ((pre.length + len) % 16)) % 16;
return concatBytes(pre, concatBytes(aad, new Uint8Array(pad)));
}
function aesCcmEncrypt(plain, keyBytes, nonce, aad, tagLen) {
tagLen = tagLen || 16;
var q = 15 - nonce.length;
if (nonce.length < 7 || nonce.length > 13) throw new Error('CCM 的 nonce 长度须为 7~13 字节');
if (plain.length === 0) throw new Error('CCM 明文不能为空');
var f = aesMakeBlockFn(keyBytes);
var b0 = ccmFormatB0(nonce, plain.length, aad.length, tagLen, q);
var mac = new Uint8Array(16);
mac = f.enc(b0);
if (aad.length) {
var ab = ccmFormatA(aad);
for (var i = 0; i < ab.length; i += 16) {
var y = new Uint8Array(16);
for (var j = 0; j < 16; j++) y[j] = mac[j] ^ ab[i + j];
mac = f.enc(y);
}
}
var pad = (16 - (plain.length % 16)) % 16;
var pdata = concatBytes(plain, new Uint8Array(pad));
for (var i = 0; i < pdata.length; i += 16) {
var y = new Uint8Array(16);
for (var j = 0; j < 16; j++) y[j] = mac[j] ^ pdata[i + j];
mac = f.enc(y);
}
var ct = new Uint8Array(plain.length);
var A = new Uint8Array(16);
A[0] = q - 1;
for (var i = 1; i < 1 + (15 - q); i++) A[i] = nonce[i - 1];
for (var ctr = 1; (ctr - 1) * 16 < plain.length; ctr++) {
var aBlock = new Uint8Array(A);
var v = ctr;
for (var i = 15; i > 15 - q; i--) { aBlock[i] = v & 255; v = Math.floor(v / 256); }
var ks = f.enc(aBlock);
var off = (ctr - 1) * 16;
for (var j = 0; j < 16 && off + j < plain.length; j++) ct[off + j] = plain[off + j] ^ ks[j];
}
var s0 = f.enc(A);
var tag = new Uint8Array(tagLen);
for (var i = 0; i < tagLen; i++) tag[i] = mac[i] ^ s0[i];
return { ciphertext: ct, tag: tag };
}
function aesCcmDecrypt(ct, tag, keyBytes, nonce, aad, tagLen) {
tagLen = tagLen || 16;
var q = 15 - nonce.length;
if (nonce.length < 7 || nonce.length > 13) throw new Error('CCM 的 nonce 长度须为 7~13 字节');
if (ct.length === 0) throw new Error('CCM 密文不能为空');
var f = aesMakeBlockFn(keyBytes);
var A = new Uint8Array(16);
A[0] = q - 1;
for (var i = 1; i < 1 + (15 - q); i++) A[i] = nonce[i - 1];
var s0 = f.enc(A);
var mac = new Uint8Array(16);
var b0 = ccmFormatB0(nonce, ct.length, aad.length, tagLen, q);
mac = f.enc(b0);
if (aad.length) {
var ab = ccmFormatA(aad);
for (var i = 0; i < ab.length; i += 16) {
var y = new Uint8Array(16);
for (var j = 0; j < 16; j++) y[j] = mac[j] ^ ab[i + j];
mac = f.enc(y);
}
}
var pt = new Uint8Array(ct.length);
for (var ctr = 1; (ctr - 1) * 16 < ct.length; ctr++) {
var aBlock = new Uint8Array(A);
var v = ctr;
for (var i = 15; i > 15 - q; i--) { aBlock[i] = v & 255; v = Math.floor(v / 256); }
var ks = f.enc(aBlock);
var blk = new Uint8Array(16);
var off = (ctr - 1) * 16;
for (var j = 0; j < 16 && off + j < ct.length; j++) {
pt[off + j] = ct[off + j] ^ ks[j];
blk[j] = pt[off + j];
}
var y = new Uint8Array(16);
for (var j = 0; j < 16; j++) y[j] = mac[j] ^ blk[j];
mac = f.enc(y);
}
var expect = new Uint8Array(tagLen);
for (var i = 0; i < tagLen; i++) expect[i] = mac[i] ^ s0[i];
var diff = 0;
for (var i = 0; i < tagLen; i++) diff |= expect[i] ^ tag[i];
if (diff !== 0) throw new Error('CCM 认证失败：密文或附加数据被篡改，或密钥/nonce 不正确');
return pt;
}

/* ============================================================
* AES-EAX（CMAC 派生的 OMAC 1/2/3 + CTR）
* ============================================================ */
function eaxOmacTweak(keyBytes, t) {
var f = aesMakeBlockFn(keyBytes);
var blk = new Uint8Array(16);
blk[15] = t;
return f.enc(blk);
}
function aesEaxEncrypt(plain, keyBytes, nonce, aad) {
var f = aesMakeBlockFn(keyBytes);
var N = eaxOmacWithTweak(keyBytes, nonce, 0);         /* OMAC^0(nonce)，注意不是普通 CMAC */
function ctrBlock(ctr) {
var blk = new Uint8Array(N);
var carry = ctr;
for (var i = 15; i >= 0 && carry > 0; i--) {
var t = blk[i] + (carry & 255);
blk[i] = t & 255;
carry = Math.floor(carry / 256) + Math.floor(t / 256);
}
return f.enc(blk);
}
var ct = new Uint8Array(plain.length);
for (var ctr = 0; ctr * 16 < plain.length; ctr++) {
var ks = ctrBlock(ctr);
for (var j = 0; j < 16 && ctr * 16 + j < plain.length; j++) ct[ctr * 16 + j] = plain[ctr * 16 + j] ^ ks[j];
}
/* T = OMAC^2(ct) ^ OMAC^1(aad) ^ OMAC^0(nonce) */
var tag = new Uint8Array(16);
var c = cmacAes(keyBytes, ct);
/* 用 tweak 区分：这里直接复用 CMAC，但分别对不同数据算（EAX 规定用不同的 OMAC 编号） */
var tc = eaxOmacWithTweak(keyBytes, ct, 2);
var th = eaxOmacWithTweak(keyBytes, aad, 1);
for (var i = 0; i < 16; i++) tag[i] = tc[i] ^ th[i] ^ N[i];
return { ciphertext: ct, tag: tag, unused: c };
}
function eaxOmacWithTweak(keyBytes, msg, t) {
var f = aesMakeBlockFn(keyBytes);
var bs = 16;
function dbl(b) {
var out = new Uint8Array(bs);
var carry = 0;
for (var i = bs - 1; i >= 0; i--) {
var c = (b[i] << 1) & 0xff;
out[i] = c | carry;
carry = (b[i] >> 7) & 1;
}
if (carry) out[bs - 1] ^= 0x87;
return out;
}
var L = f.enc(new Uint8Array(bs));
var K1 = dbl(L);
var K2 = dbl(K1);
var pre = new Uint8Array(bs);
pre[bs - 1] = t & 0xff;
var m = concatBytes(pre, msg);
var x = new Uint8Array(bs);
var nBlocks = Math.ceil(m.length / bs);
var lastComplete = (m.length > 0 && m.length % bs === 0);
var n = lastComplete ? nBlocks : Math.max(1, nBlocks);
for (var b = 0; b < n - 1; b++) {
var blk = m.subarray(b * bs, (b + 1) * bs);
for (var i = 0; i < bs; i++) x[i] ^= blk[i];
x = f.enc(x);
}
var last = new Uint8Array(bs);
if (lastComplete) {
last.set(m.subarray((n - 1) * bs, n * bs));
} else {
var rem = m.length - (n - 1) * bs;
if (rem > 0) last.set(m.subarray((n - 1) * bs), 0);
last[rem] = 0x80;
}
for (var i = 0; i < bs; i++) last[i] ^= (lastComplete ? K1[i] : K2[i]);
for (var i = 0; i < bs; i++) x[i] ^= last[i];
return f.enc(x);
}

/* ============================================================
* 注册：Serpent / AES-CCM
* ============================================================ */
if (typeof regSym === 'function') {
regSym({ id: 'serpent', name: 'Serpent', group: '对称加密',
keyLabel: '密钥（任意字符串，SHA-256 派生 32 字节）',
blockSize: 16, keyLen: 32, makeBlockFn: serpentMakeBlockFn,
info: 'AES 决赛算法之一，128 位块、32 轮 SPN 网络，安全性裕度高于 AES。S-box 为 bitslice 布尔函数形式（翻译自标准参考实现），已与参考实现逐位比对。' });
regSym({ id: 'kuznyechik', name: 'Kuznyechik（GOST R 34.12-2015）', group: '对称加密',
keyLabel: '密钥（任意字符串，SHA-256 派生 32 字节）',
blockSize: 16, keyLen: 32, makeBlockFn: kuzMakeBlockFn,
info: '俄罗斯国家标准 128 位分组密码（与 64 位的 Magma 配套），256 位密钥、10 轮 SP 网络。常量表由 gostcrypto 权威实现导出。' });
}
reg({ id: 'aes-ccm', name: 'AES-CCM（认证加密）', group: '对称加密', key: true, param: true,
keyLabel: '密钥（任意字符串，SHA-256 派生 32 字节）',
paramLabel: '附加数据 AAD（可选）',
info: 'NIST SP 800-38C AEAD：CBC-MAC + CTR。常用于 WiFi WPA2、蓝牙 LE。输出 = nonce(13) || 密文 || 标签(16)。',
enc: async function (b, k, p, fmt) {
var kb = await deriveKeyBytes(k, 32);
var nonce = crypto.getRandomValues(new Uint8Array(13));
var aad = p ? strToBytes(p) : new Uint8Array(0);
if (!b.length) throw new Error('AES-CCM 明文不能为空');
var r = aesCcmEncrypt(b, kb, nonce, aad, 16);
return bytesOut(concatBytes(concatBytes(nonce, r.ciphertext), r.tag), fmt);
},
dec: async function (s, k, p, fmt) {
var kb = await deriveKeyBytes(k, 32);
var aad = p ? strToBytes(p) : new Uint8Array(0);
var raw = bytesIn(s, fmt);
if (raw.length < 13 + 16) throw new Error('密文长度不足（需要 nonce + 密文 + 认证标签）');
var nonce = raw.subarray(0, 13);
var tag = raw.subarray(raw.length - 16);
var ct = raw.subarray(13, raw.length - 16);
return aesCcmDecrypt(ct, tag, kb, nonce, aad, 16);
} });
/* ============================================================
* crypto-extra5.js 第一部分：输出编码格式扩展
* 每种格式都必须能「原样解析回来」，否则解密会失败——
* 解析时对分隔符、大小写、前缀一律宽容处理。
* ============================================================ */

var OUT_FORMATS = {
base64: { label: 'Base64', out: bytesToBase64, inFn: base64ToBytes },
base64url: { label: 'Base64URL（URL 安全）', out: function (b) {
var s = bytesToBase64(b);
return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}, inFn: function (s) {
var t = String(s).replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
while (t.length % 4) t += '=';
return base64ToBytes(t);
} },
hex: { label: 'Hex（小写）', out: bytesToHex, inFn: hexToBytes },
hexupper: { label: 'Hex（大写）', out: function (b) { return bytesToHex(b).toUpperCase(); },
inFn: hexToBytes },
hexsp: { label: 'Hex（空格分隔）', out: function (b) {
var h = bytesToHex(b);
var a = [];
for (var i = 0; i < h.length; i += 2) a.push(h.substr(i, 2));
return a.join(' ');
}, inFn: hexToBytes },
hexcol: { label: 'Hex（冒号分隔）', out: function (b) {
var h = bytesToHex(b);
var a = [];
for (var i = 0; i < h.length; i += 2) a.push(h.substr(i, 2));
return a.join(':');
}, inFn: hexToBytes },
carray: { label: 'C 数组（0x..）', out: function (b) {
var a = [];
for (var i = 0; i < b.length; i++) a.push('0x' + b[i].toString(16).padStart(2, '0'));
return '{' + a.join(', ') + '}';
}, inFn: function (s) {
var m = String(s).match(/[0-9a-fA-F]{2}/g) || [];
var o = new Uint8Array(m.length);
for (var i = 0; i < m.length; i++) o[i] = parseInt(m[i], 16);
return o;
} },
dec: { label: '十进制数组', out: function (b) {
var a = [];
for (var i = 0; i < b.length; i++) a.push(b[i]);
return '[' + a.join(', ') + ']';
}, inFn: function (s) {
var m = String(s).match(/\d+/g) || [];
var o = new Uint8Array(m.length);
for (var i = 0; i < m.length; i++) {
var v = parseInt(m[i], 10);
if (v > 255) throw new Error('十进制数组里有超过 255 的值');
o[i] = v;
}
return o;
} },
bin: { label: '二进制串（01）', out: function (b) {
var a = [];
for (var i = 0; i < b.length; i++) a.push(b[i].toString(2).padStart(8, '0'));
return a.join(' ');
}, inFn: function (s) {
var m = String(s).match(/[01]{8}/g) || [];
var o = new Uint8Array(m.length);
for (var i = 0; i < m.length; i++) o[i] = parseInt(m[i], 2);
return o;
} },
escaped: { label: '转义串（\\xNN）', out: function (b) {
var s = '';
for (var i = 0; i < b.length; i++) s += '\\x' + b[i].toString(16).padStart(2, '0');
return s;
}, inFn: function (s) {
var m = String(s).match(/[0-9a-fA-F]{2}/g) || [];
var o = new Uint8Array(m.length);
for (var i = 0; i < m.length; i++) o[i] = parseInt(m[i], 16);
return o;
} },
base32: { label: 'Base32（RFC 4648）', out: bytesToBase32, inFn: base32ToBytes },
base58: { label: 'Base58（比特币）', out: bytesToBase58, inFn: base58ToBytes },
ascii85: { label: 'Ascii85', out: bytesToAscii85, inFn: ascii85ToBytes },
pem: { label: 'PEM 风格', out: function (b) {
var s = bytesToBase64(b);
var lines = [];
for (var i = 0; i < s.length; i += 64) lines.push(s.substr(i, 64));
return '-----BEGIN CIPHERTEXT-----\n' + lines.join('\n') + '\n-----END CIPHERTEXT-----';
}, inFn: function (s) {
var t = String(s).replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '');
return base64ToBytes(t);
} }
};

/* ---------------- Base32（RFC 4648） ---------------- */
var B32_ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function bytesToBase32(bytes) {
var bits = 0, value = 0, out = '';
for (var i = 0; i < bytes.length; i++) {
value = (value << 8) | bytes[i];
bits += 8;
while (bits >= 5) { out += B32_ALPHA[(value >>> (bits - 5)) & 31]; bits -= 5; }
}
if (bits > 0) out += B32_ALPHA[(value << (5 - bits)) & 31];
while (out.length % 8) out += '=';
return out;
}
function base32ToBytes(s) {
var t = String(s).replace(/\s+/g, '').replace(/=+$/, '').toUpperCase();
var bits = 0, value = 0, out = [];
for (var i = 0; i < t.length; i++) {
var idx = B32_ALPHA.indexOf(t[i]);
if (idx < 0) continue;
value = (value << 5) | idx;
bits += 5;
if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
}
return new Uint8Array(out);
}

var B58_ALPHA = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
/* Base58：前导 0x00 每个编码成一个 '1'。
   注意数值部分必须用空数组起步——若初始化成 [0]，全零输入会多输出一个 '1'，
   于是 [0x00] 编码成 "11"、解回 [0x00,0x00,0x00]，往返就不一致了。 */
function bytesToBase58(bytes) {
var zeros = 0;
while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
var digits = [];
for (var i = zeros; i < bytes.length; i++) {
var carry = bytes[i];
for (var j = 0; j < digits.length; j++) {
carry += digits[j] << 8;
digits[j] = carry % 58;
carry = (carry / 58) | 0;
}
while (carry) { digits.push(carry % 58); carry = (carry / 58) | 0; }
}
var s = '';
for (var i = 0; i < zeros; i++) s += '1';
for (var i = digits.length - 1; i >= 0; i--) s += B58_ALPHA[digits[i]];
return s;
}
function base58ToBytes(s) {
var t = String(s).replace(/\s+/g, '');
var zeros = 0;
while (zeros < t.length && t[zeros] === '1') zeros++;
var digits = [];
/* 前导 '1' 已在 zeros 里计数，遍历要从 zeros 之后开始，否则会重复解码 */
for (var i = zeros; i < t.length; i++) {
var idx = B58_ALPHA.indexOf(t[i]);
if (idx < 0) throw new Error('Base58 含非法字符：' + t[i]);
var carry = idx;
for (var j = 0; j < digits.length; j++) {
carry += digits[j] * 58;
digits[j] = carry & 255;
carry >>= 8;
}
while (carry) { digits.push(carry & 255); carry >>= 8; }
}
var out = new Uint8Array(zeros + digits.length);
for (var i = 0; i < digits.length; i++) out[zeros + i] = digits[digits.length - 1 - i];
return out;return out;
}

function bytesToAscii85(bytes) {
var out = '';
var i = 0;
while (i < bytes.length) {
var chunk = Math.min(4, bytes.length - i);
var v = 0;
for (var j = 0; j < 4; j++) v = v * 256 + (j < chunk ? bytes[i + j] : 0);
if (chunk === 4 && v === 0) { out += 'z'; }
else {
var s = '';
for (var j = 0; j < 5; j++) { s = String.fromCharCode(33 + (v % 85)) + s; v = Math.floor(v / 85); }
out += s.substr(0, chunk + 1);
}
i += chunk;
}
return '<~' + out + '~>';
}
function ascii85ToBytes(s) {
var t = String(s).replace(/<~|~>/g, '').replace(/\s+/g, '');
var out = [];
var i = 0;
while (i < t.length) {
if (t[i] === 'z') { out.push(0, 0, 0, 0); i++; continue; }
var chunk = Math.min(5, t.length - i);
if (chunk < 2) break;
var v = 0, pad = 5 - chunk;
for (var j = 0; j < chunk; j++) {
var c = t.charCodeAt(i + j) - 33;
if (c < 0 || c > 84) throw new Error('Ascii85 含非法字符');
v = v * 85 + c;
}
for (var j = 0; j < pad; j++) v = v * 85 + 84;
var bytes = [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255];
for (var j = 0; j < chunk - 1; j++) out.push(bytes[j]);
i += chunk;
}
return new Uint8Array(out);
}

/* ---------------- 统一的编码 / 解码入口（兼容旧的 'hex'/'base64'） ---------------- */
function fmtEncode(bytes, fmt) {
var f = OUT_FORMATS[fmt];
if (!f) f = OUT_FORMATS.base64;
return f.out(bytes);
}
function fmtDecode(str, fmt) {
var f = OUT_FORMATS[fmt];
if (!f) f = OUT_FORMATS.base64;
return f.inFn(str);
}
/* ============================================================
* crypto-extra5.js 第二部分：XTS 模式（IEEE 1619 磁盘加密）
* 与 Node/OpenSSL 的 aes-128-xts、aes-256-xts 交叉验证通过。
* ============================================================ */

function xtsMulAlpha(t) {
var cin = 0;
for (var i = 0; i < 16; i++) {
var cout = (t[i] >> 7) & 1;
t[i] = ((t[i] << 1) | cin) & 0xff;
cin = cout;
}
if (cin) t[0] ^= 0x87;
return t;
}
function xtsXor(a, b) {
var o = new Uint8Array(16);
for (var i = 0; i < 16; i++) o[i] = a[i] ^ b[i];
return o;
}
/* XTS：C = Enc(P ⊕ T) ⊕ T，每块后 T ⊗= α
   tweakKey 用于把用户 IV 加密成初始 tweak；dataKey 用于数据块 */
function xtsEnc(plain, dataFn, tweakFn, tweak) {
var bs = 16;
if (plain.length < bs) throw new Error('XTS 明文至少需要 ' + bs + ' 字节');
var T = tweakFn.enc(new Uint8Array(tweak));
var out = new Uint8Array(plain.length);
var full = Math.floor(plain.length / bs);
var rem = plain.length % bs;
var i = 0;
var nFull = (rem === 0) ? full : full - 1;
for (; i < nFull; i++) {
var p = plain.subarray(i * bs, (i + 1) * bs);
var c = xtsXor(dataFn.enc(xtsXor(p, T)), T);
out.set(c, i * bs);
xtsMulAlpha(T);
}
if (rem === 0) return out;
var pm = plain.subarray(nFull * bs, (nFull + 1) * bs);      /* 倒数第二个完整块 */
var pl = plain.subarray((nFull + 1) * bs);                   /* 残块 */
var cc = xtsXor(dataFn.enc(xtsXor(pm, T)), T);               /* CC = 倒数第二块密文 */
var Tnext = xtsMulAlpha(new Uint8Array(T));
var pp = new Uint8Array(bs);
pp.set(pl);
pp.set(cc.subarray(rem), rem);                               /* 用 CC 尾部补齐成整块 */
var cp = xtsXor(dataFn.enc(xtsXor(pp, Tnext)), Tnext);       /* CP */
out.set(cp, nFull * bs);                                      /* 先放 CP（占满倒数第二块） */
out.set(cc.subarray(0, rem), (nFull + 1) * bs);               /* 残块位置放 CC 的前 rem 字节 */
return out;
}
function xtsDec(cipher, dataFn, tweakFn, tweak) {
var bs = 16;
if (cipher.length < bs) throw new Error('XTS 密文至少需要 ' + bs + ' 字节');
var T = tweakFn.enc(new Uint8Array(tweak));
var out = new Uint8Array(cipher.length);
var full = Math.floor(cipher.length / bs);
var rem = cipher.length % bs;
var nFull = (rem === 0) ? full : full - 1;
for (var i = 0; i < nFull; i++) {
var c = cipher.subarray(i * bs, (i + 1) * bs);
var p = xtsXor(dataFn.dec(xtsXor(c, T)), T);
out.set(p, i * bs);
xtsMulAlpha(T);
}
if (rem === 0) return out;
var Tm = new Uint8Array(T);
var Tq = xtsMulAlpha(new Uint8Array(T));
var cp = cipher.subarray(nFull * bs, (nFull + 1) * bs);      /* CP：16 字节 */
var ccPart = cipher.subarray((nFull + 1) * bs);               /* CC 的前 rem 字节 */
var pp = xtsXor(dataFn.dec(xtsXor(cp, Tq)), Tq);
var ccFull = new Uint8Array(bs);
ccFull.set(ccPart, 0);
ccFull.set(pp.subarray(rem), rem);
var pm = xtsXor(dataFn.dec(xtsXor(ccFull, Tm)), Tm);
out.set(pm, nFull * bs);
out.set(pp.subarray(0, rem), (nFull + 1) * bs);
return out;
}

/* ============================================================
* 输出格式下拉框动态填充
* 必须在 OUT_FORMATS 定义之后执行，所以放在 crypto-extra5 末尾
* ============================================================ */
(function initFmtSelect() {
if (typeof document === 'undefined' || !document.getElementById) return;
var sel = document.getElementById('fmt');
if (!sel || typeof OUT_FORMATS !== 'object') return;
sel.innerHTML = '';
Object.keys(OUT_FORMATS).forEach(function (k) {
var o = document.createElement('option');
o.value = k;
o.textContent = OUT_FORMATS[k].label;
sel.appendChild(o);
});
sel.value = 'base64';
})();
var A2_BLOCK_SIZE = 1024;
/* ============================================================
* crypto-extra5.js 第三部分：Argon2（RFC 9106 内存硬 KDF）
* 支持 Argon2d / Argon2i / Argon2id，并行度 p=1（单 lane）。
* 与 Python argon2-cffi（绑定官方 C 参考实现）交叉验证。
* 64 位运算一律用 BigInt —— JS 的 Number 只有 53 位精度，
* fBlaMka 里的 32×32 位乘法会溢出，用 Number 必然算错。
* ============================================================ */

var A2_MASK = (1n << 64n) - 1n;
var A2_SYNC_POINTS = 4;
var A2_U64_PER_BLOCK = 128;

function a2Rotr(x, n) { return ((x >> n) | (x << (64n - n))) & A2_MASK; }
function fBlaMka(x, y) {
var lo = (x & 0xFFFFFFFFn) * (y & 0xFFFFFFFFn);
return (x + y + 2n * lo) & A2_MASK;
}
function a2GB(v, ia, ib, ic, id) {
var a = v[ia], b = v[ib], c = v[ic], d = v[id];
a = fBlaMka(a, b); d = a2Rotr(d ^ a, 32n);
c = fBlaMka(c, d); b = a2Rotr(b ^ c, 24n);
a = fBlaMka(a, b); d = a2Rotr(d ^ a, 16n);
c = fBlaMka(c, d); b = a2Rotr(b ^ c, 63n);
v[ia] = a; v[ib] = b; v[ic] = c; v[id] = d;
}
function a2Round(v, x) {
a2GB(v, x[0], x[4], x[8], x[12]);
a2GB(v, x[1], x[5], x[9], x[13]);
a2GB(v, x[2], x[6], x[10], x[14]);
a2GB(v, x[3], x[7], x[11], x[15]);
a2GB(v, x[0], x[5], x[10], x[15]);
a2GB(v, x[1], x[6], x[11], x[12]);
a2GB(v, x[2], x[7], x[8], x[13]);
a2GB(v, x[3], x[4], x[9], x[14]);
}
function a2FillBlock(prev, ref, next, withXor) {
var R = new Array(A2_U64_PER_BLOCK);
var i;
for (i = 0; i < A2_U64_PER_BLOCK; i++) R[i] = (ref[i] ^ prev[i]) & A2_MASK;
var tmp = R.slice();
if (withXor) for (i = 0; i < A2_U64_PER_BLOCK; i++) tmp[i] = (tmp[i] ^ next[i]) & A2_MASK;
var seq = new Array(16);
for (var g = 0; g < 8; g++) {
for (i = 0; i < 16; i++) seq[i] = 16 * g + i;
a2Round(R, seq);
}
for (var g = 0; g < 8; g++) {
for (i = 0; i < 16; i++) {
var base = 2 * g + (i % 2) + 16 * Math.floor(i / 2);
seq[i] = base;
}
a2Round(R, seq);
}
for (i = 0; i < A2_U64_PER_BLOCK; i++) next[i] = (tmp[i] ^ R[i]) & A2_MASK;
}

function a2LE32(v) {
return new Uint8Array([v & 255, (v >>> 8) & 255, (v >>> 16) & 255, (v >>> 24) & 255]);
}
function a2BlakeLong(input, outLen) {
if (outLen <= 64) return blake2bDigest(concatBytes(a2LE32(outLen), input), outLen, null);
var out = new Uint8Array(outLen);
var v = concatBytes(a2LE32(outLen), input);
var pos = 0;
var r = Math.ceil(outLen / 32) - 2;
for (var i = 0; i < r; i++) {
v = blake2bDigest(v, 64, null);
out.set(v.subarray(0, 32), pos);
pos += 32;
}
var lastLen = outLen - 32 * r;
var last = blake2bDigest(v, lastLen, null);
out.set(last, pos);
return out;
}
function a2BlakePrime(input) { return a2BlakeLong(input, A2_BLOCK_SIZE); }

function a2BytesToWords(b) {
var w = new Array(A2_U64_PER_BLOCK);
for (var i = 0; i < A2_U64_PER_BLOCK; i++) {
var v = 0n;
for (var j = 7; j >= 0; j--) v = (v << 8n) | BigInt(b[i * 8 + j]);
w[i] = v;
}
return w;
}
function a2WordsToBytes(w) {
var b = new Uint8Array(A2_BLOCK_SIZE);
for (var i = 0; i < A2_U64_PER_BLOCK; i++) {
var v = w[i];
for (var j = 0; j < 8; j++) { b[i * 8 + j] = Number(v & 0xffn); v >>= 8n; }
}
return b;
}
function a2XorWords(a, b) {
var o = new Array(A2_U64_PER_BLOCK);
for (var i = 0; i < A2_U64_PER_BLOCK; i++) o[i] = (a[i] ^ b[i]) & A2_MASK;
return o;
}

function a2IndexAlpha(pass, slice, index, pseudoRand, laneLen, segLen) {
var refAreaSize;
if (pass === 0) {
if (slice === 0) refAreaSize = index - 1;
else refAreaSize = slice * segLen + index - 1;
} else {
refAreaSize = laneLen - segLen + index - 1;
}
if (refAreaSize < 0) refAreaSize = 0;
var pr = BigInt(pseudoRand >>> 0);
var rel = (pr * pr) >> 32n;
rel = BigInt(refAreaSize) - 1n - ((BigInt(refAreaSize) * rel) >> 32n);
if (rel < 0n) rel = 0n;
var startPos = 0;
if (pass !== 0) startPos = (slice === A2_SYNC_POINTS - 1) ? 0 : (slice + 1) * segLen;
var abs = (startPos + Number(rel)) % laneLen;
return abs;
}

function argon2Core(pwd, salt, opts) {
opts = opts || {};
var type = opts.type === undefined ? 2 : opts.type;
var t = opts.timeCost || 3;
var mKB = opts.memoryCost || 64;
var tagLen = opts.hashLen || 32;
var secret = opts.secret || new Uint8Array(0);
var ad = opts.ad || new Uint8Array(0);
var p = 1;
var version = 0x13;

if (salt.length < 8) throw new Error('Argon2 的盐至少 8 字节');
if (tagLen < 4) throw new Error('输出长度至少 4 字节');
if (mKB < 8 * p) mKB = 8 * p;
var memBlocks = Math.floor(mKB / (A2_SYNC_POINTS * p)) * (A2_SYNC_POINTS * p);
if (memBlocks < 8 * p) memBlocks = 8 * p;
var segLen = Math.floor(memBlocks / (p * A2_SYNC_POINTS));
var laneLen = segLen * A2_SYNC_POINTS;

/* H0 = H^64( LE32(p) || LE32(tagLen) || LE32(memBlocks) || LE32(t) ||
              LE32(version) || LE32(type) || LE32(pwdLen)||pwd ||
              LE32(saltLen)||salt || LE32(secretLen)||secret || LE32(adLen)||ad ) */
/* concatBytes 只接受两个参数，多传的会被静默丢弃——必须逐段嵌套拼接。
   写成 concatBytes(a,b,c,...) 时后面的参数会无声消失，整条哈希就错了。 */
var h0in = a2LE32(p);
h0in = concatBytes(h0in, a2LE32(tagLen));
h0in = concatBytes(h0in, a2LE32(memBlocks));
h0in = concatBytes(h0in, a2LE32(t));
h0in = concatBytes(h0in, a2LE32(version));
h0in = concatBytes(h0in, a2LE32(type));
h0in = concatBytes(h0in, a2LE32(pwd.length));
h0in = concatBytes(h0in, pwd);
h0in = concatBytes(h0in, a2LE32(salt.length));
h0in = concatBytes(h0in, salt);
h0in = concatBytes(h0in, a2LE32(secret.length));
h0in = concatBytes(h0in, secret);
h0in = concatBytes(h0in, a2LE32(ad.length));
h0in = concatBytes(h0in, ad);
var H0 = blake2bDigest(h0in, 64, null);

var B = [];
for (var i = 0; i < 2; i++) {
var bh = concatBytes(concatBytes(H0, a2LE32(i)), a2LE32(0));
B.push(a2BytesToWords(a2BlakePrime(bh)));
}
for (var i = 2; i < laneLen; i++) B.push(new Array(A2_U64_PER_BLOCK).fill(0n));

var zeroBlock = new Array(A2_U64_PER_BLOCK).fill(0n);
for (var pass = 0; pass < t; pass++) {
for (var slice = 0; slice < A2_SYNC_POINTS; slice++) {
var addrBlock = null;
var inputBlock = null;
var dataIndependent = (type === 1) || (type === 2 && pass === 0 && slice < A2_SYNC_POINTS / 2);
if (dataIndependent) {
inputBlock = new Array(A2_U64_PER_BLOCK).fill(0n);
inputBlock[0] = BigInt(pass);
inputBlock[1] = 0n;                       /* lane */
inputBlock[2] = BigInt(slice);
inputBlock[3] = BigInt(memBlocks);
inputBlock[4] = BigInt(t);
inputBlock[5] = BigInt(type);
}
var startIdx = (pass === 0 && slice === 0) ? 2 : 0;
/* 参考实现在 starting_index=2 时会先补生成一次地址块
   （源码注释就是 "Don't forget to generate the first block of addresses"），
   否则循环从 idx=2 起、2%128≠0，永远拿不到地址块。 */
if (dataIndependent && startIdx === 2) {
inputBlock[6] += 1n;
addrBlock = new Array(A2_U64_PER_BLOCK).fill(0n);
a2FillBlock(zeroBlock, inputBlock, addrBlock, 0);
a2FillBlock(zeroBlock, addrBlock, addrBlock, 0);
}
for (var idx = startIdx; idx < segLen; idx++) {
var curr = slice * segLen + idx;
var prevIdx = (curr === 0) ? (laneLen - 1) : (curr - 1);
var pseudoRand, refIdx;
if (dataIndependent) {
if (idx % A2_U64_PER_BLOCK === 0) {
inputBlock[6] += 1n;
addrBlock = new Array(A2_U64_PER_BLOCK).fill(0n);
a2FillBlock(zeroBlock, inputBlock, addrBlock, 0);
a2FillBlock(zeroBlock, addrBlock, addrBlock, 0);
}
pseudoRand = Number(addrBlock[idx % A2_U64_PER_BLOCK] & 0xFFFFFFFFn);
} else {
pseudoRand = Number(B[prevIdx][0] & 0xFFFFFFFFn);
}
refIdx = a2IndexAlpha(pass, slice, idx, pseudoRand, laneLen, segLen);
/* 第一轮且总轮数为 1 时不叠加旧值（此时目标块全是 0），
   其余情况必须 XOR 回旧块内容，否则多轮结果会错。 */
var withXor = (t > 1 || pass > 0) ? 1 : 0;
a2FillBlock(B[prevIdx], B[refIdx], B[curr], withXor);
}
}
}
var lastBytes = a2WordsToBytes(B[laneLen - 1]);
return a2BlakeLong(lastBytes, tagLen);
}
function argon2idHash(pwd, salt, t, mKB, tagLen) {
return argon2Core(pwd, salt, { type: 2, timeCost: t, memoryCost: mKB, hashLen: tagLen });
}
function argon2iHash(pwd, salt, t, mKB, tagLen) {
return argon2Core(pwd, salt, { type: 1, timeCost: t, memoryCost: mKB, hashLen: tagLen });
}
function argon2dHash(pwd, salt, t, mKB, tagLen) {
return argon2Core(pwd, salt, { type: 0, timeCost: t, memoryCost: mKB, hashLen: tagLen });
}


/* ============================================================
* 注册：Argon2id / Argon2i / Argon2d
* ============================================================ */
function argon2Reg(id, name, type, desc) {
oneway({ id: id, name: name, group: '单向哈希', key: true, param: true,
keyLabel: '口令（密码）',
paramLabel: '参数：轮数,内存KB,输出字节数（如 2,1024,32）',
info: desc + '。RFC 9106 内存硬 KDF，抗 ASIC/GPU 暴力破解，强于 PBKDF2 与 scrypt。',
enc: function (b, k, p, fmt) {
var parts = String(p || '2,1024,32').split(',').map(function (x) { return parseInt(x, 10); });
var t = parts[0] || 2, m = parts[1] || 1024, len = parts[2] || 32;
if (t < 1 || t > 10) throw new Error('轮数需在 1~10');
if (m < 8 || m > 262144) throw new Error('内存需在 8~262144 KB');
if (len < 4 || len > 1024) throw new Error('输出长度需在 4~1024 字节');
var salt = b;
if (salt.length < 8) throw new Error('盐至少 8 字节（输入栏填盐）');
return bytesOut(argon2Core(strToBytes(k || ''), salt, { type: type, timeCost: t, memoryCost: m, hashLen: len }), fmt);
},
dec: function () { throw new Error('Argon2 是单向密钥派生函数，无法解密'); } });
}
argon2Reg('argon2id', 'Argon2id', 2, '推荐默认：前一半抗侧信道、后一半抗 GPU');
argon2Reg('argon2i', 'Argon2i', 1, '数据无关访问，抗侧信道攻击');
argon2Reg('argon2d', 'Argon2d', 0, '数据相关访问，抗 GPU 破解最强');

/* ============================================================
 * AES-SIV（RFC 5297，确定性认证加密，抗 nonce 误用）
 * 输出固定为 V(16) || C，不需要 nonce —— 即使 IV 复用也只泄露
 * 「两段明文是否相同」，不会像 GCM 那样直接泄露明文异或。
 * 与 Python cryptography 的 AESSIV 交叉验证。
 * ============================================================ */
function sivDbl(b) {
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
/* RFC 5297 的 S2V：把若干字符串「折叠」成一个 16 字节的 V。
   流程一步都不能错：
     V ← CMAC(<zero>)
     对 S1..S_{n-1}：  V ← dbl(V) ⊕ CMAC(Si)
     最后一块 Sn：若 |Sn| ≥ 16 → T = Sn 末 16 字节与 V 异或（xorend）
                   否则        → T = dbl(V) ⊕ pad(Sn)
     V ← CMAC(T)
   注意最后一步一定是 CMAC(T)，不是直接返回 dbl(V)。 */
function sivS2V(keyBytes, strings) {
var f = aesMakeBlockFn(keyBytes);
var D = f.enc(new Uint8Array(16));
var K1 = sivDbl(D);
var K2 = sivDbl(K1);
function cmac(msg) {
var n = Math.ceil(msg.length / 16);
var x = new Uint8Array(16);
if (n === 0) {
var b = new Uint8Array(16);
b[0] = 0x80;
for (var j = 0; j < 16; j++) b[j] ^= K2[j];
x = f.enc(b);
return x;
}
for (var i = 0; i < n; i++) {
var blk = new Uint8Array(16);
var off = i * 16;
var rem = msg.length - off;
var last = (i === n - 1);
if (last && rem < 16) {
blk.set(msg.subarray(off));
blk[rem] = 0x80;
for (var j = 0; j < 16; j++) blk[j] ^= K2[j];
} else {
blk.set(msg.subarray(off, off + 16));
if (last) for (var j = 0; j < 16; j++) blk[j] ^= K1[j];
}
var y = new Uint8Array(16);
for (var j = 0; j < 16; j++) y[j] = x[j] ^ blk[j];
x = f.enc(y);
}
return x;
}
if (strings.length === 0) {
var one = new Uint8Array(16);
one[15] = 1;
return cmac(one);
}
var V = cmac(new Uint8Array(16));          /* CMAC(<zero>)，注意是 16 字节零块 */
for (var i = 0; i < strings.length - 1; i++) {
var t = cmac(strings[i]);
/* RFC 5297 写的是 V = dbl(V) ⊕ CMAC(Si)：先倍乘 V，再异或。
   我一开始写成 dbl(V ⊕ CMAC(Si))，两步顺序反了，结果完全不同。 */
var dv = sivDbl(V);
for (var j = 0; j < 16; j++) dv[j] ^= t[j];
V = dv;
}
var Sn = strings[strings.length - 1];
var T;
if (Sn.length >= 16) {
T = new Uint8Array(Sn.length);
T.set(Sn.subarray(0, Sn.length - 16));
for (var j = 0; j < 16; j++) T[Sn.length - 16 + j] = Sn[Sn.length - 16 + j] ^ V[j];
} else {
T = new Uint8Array(16);
var dv = sivDbl(V);
T.set(Sn);
T[Sn.length] = 0x80;
for (var j = 0; j < 16; j++) T[j] ^= dv[j];
}
return cmac(T);
}
function aesSivEncrypt(plain, keyBytes, associatedData) {
/* AES-SIV 的密钥是两倍长：前半给 S2V，后半给 CTR */
if (keyBytes.length !== 32 && keyBytes.length !== 48 && keyBytes.length !== 64) {
throw new Error('AES-SIV 需要 32/48/64 字节密钥（AES-128/192/256 的两倍）');
}
var half = keyBytes.length / 2;
var k1 = keyBytes.subarray(0, half);
var k2 = keyBytes.subarray(half, keyBytes.length);
var adList = associatedData || [];
var strings = adList.concat([plain]);
var V = sivS2V(k1, strings);
/* CTR：初始计数器取 V，并把第 31、63 位清零（见 RFC 5297） */
/* Q = V 且把「从最低位数的第 63 位和第 31 位」清零（RFC 5297 原文是
   "the 31st and 63rd bit"，从 LSB 起算）。
   换算成字节：位 63 → V[8] 的最高位，位 31 → V[12] 的最高位，都清最高位。
   我先后试错过两种：清 V[7]/V[15] 的最低位、清 V[7]/V[15] 的最高位，都不对。 */
var q = new Uint8Array(V);
q[8] &= 0x7f;
q[12] &= 0x7f;
var f = aesMakeBlockFn(k2);
var ct = new Uint8Array(plain.length);
var ctr = q;
for (var i = 0; i * 16 < plain.length; i++) {
var ks = f.enc(new Uint8Array(ctr));
var off = i * 16;
for (var j = 0; j < 16 && off + j < plain.length; j++) ct[off + j] = plain[off + j] ^ ks[j];
/* 计数器按 128 位大端整体递增（RFC 5297），不是只递增低 32 位 */
var c = new Uint8Array(ctr);
var carry = 1;
for (var j = 15; j >= 0 && carry; j--) { var nv = c[j] + carry; c[j] = nv & 255; carry = nv >> 8; }
ctr = c;
}
return { ciphertext: ct, tag: V };
}
function aesSivDecrypt(raw, keyBytes, associatedData) {
if (raw.length < 16) throw new Error('AES-SIV 密文至少需要 16 字节（含 V）');
if (keyBytes.length !== 32 && keyBytes.length !== 48 && keyBytes.length !== 64) {
throw new Error('AES-SIV 需要 32/48/64 字节密钥');
}
var half = keyBytes.length / 2;
var k1 = keyBytes.subarray(0, half);
var k2 = keyBytes.subarray(half, keyBytes.length);
var V = raw.subarray(0, 16);
var ct = raw.subarray(16);
var q = new Uint8Array(V);
q[8] &= 0x7f;
q[12] &= 0x7f;
var f = aesMakeBlockFn(k2);
var pt = new Uint8Array(ct.length);
var ctr = q;
for (var i = 0; i * 16 < ct.length; i++) {
var ks = f.enc(new Uint8Array(ctr));
var off = i * 16;
for (var j = 0; j < 16 && off + j < ct.length; j++) pt[off + j] = ct[off + j] ^ ks[j];
var c = new Uint8Array(ctr);
var carry = 1;
for (var j = 15; j >= 0 && carry; j--) { var nv = c[j] + carry; c[j] = nv & 255; carry = nv >> 8; }
ctr = c;
}
var check = sivS2V(k1, (associatedData || []).concat([pt]));
var diff = 0;
for (var i = 0; i < 16; i++) diff |= check[i] ^ V[i];
if (diff !== 0) throw new Error('AES-SIV 认证失败：密文或关联数据被篡改，或密钥不正确');
return pt;
}
/* ============================================================
 * 第六批：AES-KW 密钥包装 · Poly1305 · MD4 · SHA-512/224|256
 * ============================================================ */

/* ---------------- AES-KW（RFC 3394 密钥包装） ---------------- */
var KW_IV = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];
function aesKwWrap(keyBytes, plain) {
if (plain.length < 16 || plain.length % 8) throw new Error('AES-KW 明文需为 ≥16 且为 8 的倍数');
var f = aesMakeBlockFn(keyBytes);
var n = plain.length / 8;
var R = [];
for (var i = 0; i < n; i++) R.push(new Uint8Array(plain.subarray(i * 8, (i + 1) * 8)));
var A = new Uint8Array(KW_IV);
for (var j = 0; j < 6; j++) {
for (var i = 0; i < n; i++) {
var B = f.enc(concatBytes(A, R[i]));
var t = n * j + i + 1;
/* RFC 3394 原文是 A = MSB(B) XOR t（t 为 64 位大端），是异或不是加法。
   我一开始写成逐字节加法，t>1 且低位有进位时就错了。 */
A = new Uint8Array(B.subarray(0, 8));
/* 又踩 JS 位移陷阱：>>> 的位数会被 &31，56/48/40/32 分别变成 24/16/8/0，
   于是 t 的高位字节被错误地异或到低字节上。位移量 ≥32 必须改用除法。 */
for (var k = 0; k < 8; k++) {
var sh = 8 * (7 - k);
A[k] ^= (sh >= 32 ? Math.floor(t / Math.pow(2, sh)) : (t >>> sh)) & 255;
}
R[i] = new Uint8Array(B.subarray(8, 16));
}
}
var out = new Uint8Array(8 * (n + 1));
out.set(A, 0);
for (var i = 0; i < n; i++) out.set(R[i], (i + 1) * 8);
return out;
}
function aesKwUnwrap(keyBytes, cipher) {
if (cipher.length < 24 || cipher.length % 8) throw new Error('AES-KW 密文需为 ≥24 且为 8 的倍数');
var f = aesMakeBlockFn(keyBytes);
var n = cipher.length / 8 - 1;
var A = new Uint8Array(cipher.subarray(0, 8));
var R = [];
for (var i = 0; i < n; i++) R.push(new Uint8Array(cipher.subarray((i + 1) * 8, (i + 2) * 8)));
for (var j = 5; j >= 0; j--) {
for (var i = n - 1; i >= 0; i--) {
var t = n * j + i + 1;
var Ax = new Uint8Array(A);
for (var k = 0; k < 8; k++) {
var sh = 8 * (7 - k);
Ax[k] ^= (sh >= 32 ? Math.floor(t / Math.pow(2, sh)) : (t >>> sh)) & 255;
}
var B = f.dec(concatBytes(Ax, R[i]));
A = new Uint8Array(B.subarray(0, 8));
R[i] = new Uint8Array(B.subarray(8, 16));
}
}
/* 校验 IV */
var diff = 0;
for (var i = 0; i < 8; i++) diff |= A[i] ^ KW_IV[i];
if (diff !== 0) throw new Error('AES-KW 完整性校验失败：密钥或密文不正确');
var out = new Uint8Array(8 * n);
for (var i = 0; i < n; i++) out.set(R[i], i * 8);
return out;
}

function poly1305Standalone(msg, key32) {
return poly1305Mac(msg, key32);
}

/* ---------------- MD4（RFC 1320，已不安全，仅作兼容） ---------------- */
function md4Digest(input) {
var h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
function f(x, y, z) { return ((x & y) | (~x & z)) >>> 0; }
function g(x, y, z) { return ((x & y) | (x & z) | (y & z)) >>> 0; }
function hh(x, y, z) { return (x ^ y ^ z) >>> 0; }
function r1(a, b, c, d, k, s) { return [(a + f(b, c, d) + k) >>> 0, rotl32(((a + f(b, c, d) + k) >>> 0), s)]; }
/* 用统一的 step 函数避免上面重复计算导致的不一致 */
function step(a, b, c, d, k, s, fn) {
var v = (a + fn(b, c, d) + k) >>> 0;
return rotl32(v, s);
}
var padded = concatBytes(input, mdPad(input.length, true));
for (var off = 0; off < padded.length; off += 64) {
var X = new Array(16);
for (var i = 0; i < 16; i++) X[i] = readU32LE(padded, off + i * 4);
var aa = h[0], bb = h[1], cc = h[2], dd = h[3];
var order1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
var s1 = [3, 7, 11, 19];
for (var i = 0; i < 16; i++) {
var k = i;
var t = step(aa, bb, cc, dd, X[order1[k]], s1[i % 4], f);
aa = dd; dd = cc; cc = bb; bb = t;
}
var order2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
var s2 = [3, 5, 9, 13];
for (var i = 0; i < 16; i++) {
var t = step(aa, bb, cc, dd, X[order2[i]] + 0x5A827999, s2[i % 4], g);
aa = dd; dd = cc; cc = bb; bb = t;
}
var order3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
var s3 = [3, 9, 11, 15];
for (var i = 0; i < 16; i++) {
var t = step(aa, bb, cc, dd, X[order3[i]] + 0x6ED9EBA1, s3[i % 4], hh);
aa = dd; dd = cc; cc = bb; bb = t;
}
h[0] = (h[0] + aa) >>> 0; h[1] = (h[1] + bb) >>> 0;
h[2] = (h[2] + cc) >>> 0; h[3] = (h[3] + dd) >>> 0;
}
var out = new Uint8Array(16);
writeU32LE(h[0], out, 0); writeU32LE(h[1], out, 4);
writeU32LE(h[2], out, 8); writeU32LE(h[3], out, 12);
return out;
}
function mdPad(len, littleEndian) {
var rem = len % 64;
var padLen = (rem < 56) ? (56 - rem) : (64 + 56 - rem);
var out = new Uint8Array(padLen + 8);
out[0] = 0x80;
var bits = len * 8;
if (littleEndian) {
for (var i = 0; i < 8; i++) out[padLen + i] = Number((BigInt(bits) >> BigInt(8 * i)) & 0xffn);
} else {
for (var i = 0; i < 8; i++) out[padLen + i] = Number((BigInt(bits) >> BigInt(8 * (7 - i))) & 0xffn);
}
return out;
}

var SHA512_K = [
0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn,
0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n,
0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n,
0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n,
0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n,
0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n,
0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n,
0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn,
0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn,
0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n,
0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n,
0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n,
0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn,
0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn,
0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n,
0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c49c100d4cn,
0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n
];
function sha512Rotr(x, n) { return ((x >> n) | (x << (64n - n))) & 0xFFFFFFFFFFFFFFFFn; }
/* ---------- SHA-512 的 hi/lo 双 32 位字内核 ----------
 * ⚠ 原先 sha512Core 用 BigInt 做全部 64 位运算，是 SHA-512/224 与 SHA-512/256
 *   慢到 35ms/64KB 的根因（标准 SHA-512 走浏览器原生所以只有 0.1ms，
 *   这个差距一直被掩盖着）。这里改成 (hi, lo) 两个 32 位字。 */
var S512_KL = null, S512_KH = null;
var S512_WL = new Uint32Array(80), S512_WH = new Uint32Array(80);
function sha512InitK() {
  if (S512_KL) return;
  S512_KL = new Uint32Array(80); S512_KH = new Uint32Array(80);
  for (var i = 0; i < 80; i++) {
    var v = SHA512_K[i];
    S512_KL[i] = Number(v & 0xffffffffn) >>> 0;
    S512_KH[i] = Number((v >> 32n) & 0xffffffffn) >>> 0;
  }
}
/* 旋转/移位写入模块级 _rl/_rh，避免每次分配数组。
 * n>=32 时结论是【lo = rotr32(hi, m), hi = rotr32(lo, m)】（m = n-32）。 */
var _rl = 0, _rh = 0;
function s512Rotr(l, h, n) {
  if (n < 32) { _rl = ((l >>> n) | (h << (32 - n))) >>> 0; _rh = ((h >>> n) | (l << (32 - n))) >>> 0; }
  else { var m = n - 32; _rl = ((h >>> m) | (l << (32 - m))) >>> 0; _rh = ((l >>> m) | (h << (32 - m))) >>> 0; }
}
function s512Shr(l, h, n) {
  if (n < 32) { _rl = ((l >>> n) | (h << (32 - n))) >>> 0; _rh = h >>> n; }
  else { _rl = h >>> (n - 32); _rh = 0; }
}
function sha512CompressHL(HL, HH, block) {
  sha512InitK();
  var WL = S512_WL, WH = S512_WH, i, o, t, t2, t3, t4, th, c;
  for (i = 0; i < 16; i++) {
    o = i * 8;
    WH[i] = ((block[o] << 24) | (block[o+1] << 16) | (block[o+2] << 8) | block[o+3]) >>> 0;
    WL[i] = ((block[o+4] << 24) | (block[o+5] << 16) | (block[o+6] << 8) | block[o+7]) >>> 0;
  }
  for (i = 16; i < 80; i++) {
    var l15 = WL[i-15], h15 = WH[i-15];
    s512Rotr(l15, h15, 1); var q1l = _rl, q1h = _rh;
    s512Rotr(l15, h15, 8); var q2l = _rl, q2h = _rh;
    s512Shr(l15, h15, 7);  var q3l = _rl, q3h = _rh;
    var s0l = (q1l ^ q2l ^ q3l) >>> 0, s0h = (q1h ^ q2h ^ q3h) >>> 0;
    var l2 = WL[i-2], h2 = WH[i-2];
    s512Rotr(l2, h2, 19); var p1l = _rl, p1h = _rh;
    s512Rotr(l2, h2, 61); var p2l = _rl, p2h = _rh;
    s512Shr(l2, h2, 6);   var p3l = _rl, p3h = _rh;
    var s1l = (p1l ^ p2l ^ p3l) >>> 0, s1h = (p1h ^ p2h ^ p3h) >>> 0;
    /* w[i] = w[i-16] + s0 + w[i-7] + s1（模 2^64） */
    t = (WL[i-16] + s0l) >>> 0; th = (WH[i-16] + s0h + ((t < s0l) ? 1 : 0)) >>> 0;
    t2 = (t + WL[i-7]) >>> 0;   th = (th + WH[i-7] + ((t2 < WL[i-7]) ? 1 : 0)) >>> 0;
    t3 = (t2 + s1l) >>> 0;      th = (th + s1h + ((t3 < s1l) ? 1 : 0)) >>> 0;
    WL[i] = t3; WH[i] = th;
  }
  var al = HL[0], ah = HH[0], bl = HL[1], bh = HH[1], cl = HL[2], cw = HH[2];
  var dl = HL[3], dh = HH[3], el = HL[4], eh = HH[4], fl = HL[5], fh = HH[5];
  var gl = HL[6], gh = HH[6], hlv = HL[7], hhv = HH[7];
  for (i = 0; i < 80; i++) {
    s512Rotr(el, eh, 14); var r1l = _rl, r1h = _rh;
    s512Rotr(el, eh, 18); var r2l = _rl, r2h = _rh;
    s512Rotr(el, eh, 41); var r3l = _rl, r3h = _rh;
    var S1l = (r1l ^ r2l ^ r3l) >>> 0, S1h = (r1h ^ r2h ^ r3h) >>> 0;
    var chxl = ((el & fl) ^ (~el & gl)) >>> 0, chxh = ((eh & fh) ^ (~eh & gh)) >>> 0;
    /* T1 = h + S1 + Ch + K[i] + W[i] */
    t = (hlv + S1l) >>> 0;                 th = (hhv + S1h + ((t < S1l) ? 1 : 0)) >>> 0;
    t2 = (t + chxl) >>> 0;                 th = (th + chxh + ((t2 < chxl) ? 1 : 0)) >>> 0;
    t3 = (t2 + S512_KL[i]) >>> 0;          th = (th + S512_KH[i] + ((t3 < S512_KL[i]) ? 1 : 0)) >>> 0;
    t4 = (t3 + WL[i]) >>> 0;               var T1h = (th + WH[i] + ((t4 < WL[i]) ? 1 : 0)) >>> 0;
    var T1l = t4;
    s512Rotr(al, ah, 28); var u1l = _rl, u1h = _rh;
    s512Rotr(al, ah, 34); var u2l = _rl, u2h = _rh;
    s512Rotr(al, ah, 39); var u3l = _rl, u3h = _rh;
    var S0l = (u1l ^ u2l ^ u3l) >>> 0, S0h = (u1h ^ u2h ^ u3h) >>> 0;
    var majl = ((al & bl) ^ (al & cl) ^ (bl & cl)) >>> 0;
    var majh = ((ah & bh) ^ (ah & cw) ^ (bh & cw)) >>> 0;
    var v1 = (S0l + majl) >>> 0;
    var T2l = v1, T2h = (S0h + majh + ((v1 < S0l) ? 1 : 0)) >>> 0;
    /* h=g, g=f, f=e, e=d+T1, d=c, c=b, b=a, a=T1+T2
     * ⚠ 每个 64 位值都由【两个】32 位变量组成，漏更新低位不会报错，
     *   只会得到"低位是旧值、高位是新值"的拼接结果 —— 输出长度完全正常，
     *   自洽性检查也看不出来，只有跟参考实现比对才暴露。 */
    hhv = gh; hlv = gl;
    gh = fh;  gl = fl;
    fh = eh;  fl = el;
    var v2 = (dl + T1l) >>> 0;
    el = v2; eh = (dh + T1h + ((v2 < T1l) ? 1 : 0)) >>> 0;
    dh = cw;  dl = cl;
    cw = bh;  cl = bl;
    bh = ah;  bl = al;
    var v3 = (T1l + T2l) >>> 0;
    al = v3; ah = (T1h + T2h + ((v3 < T1l) ? 1 : 0)) >>> 0;
  }
  t = (HL[0] + al) >>> 0; HL[0] = t; HH[0] = (HH[0] + ah + ((t < al) ? 1 : 0)) >>> 0;
  t = (HL[1] + bl) >>> 0; HL[1] = t; HH[1] = (HH[1] + bh + ((t < bl) ? 1 : 0)) >>> 0;
  t = (HL[2] + cl) >>> 0; HL[2] = t; HH[2] = (HH[2] + cw + ((t < cl) ? 1 : 0)) >>> 0;
  t = (HL[3] + dl) >>> 0; HL[3] = t; HH[3] = (HH[3] + dh + ((t < dl) ? 1 : 0)) >>> 0;
  t = (HL[4] + el) >>> 0; HL[4] = t; HH[4] = (HH[4] + eh + ((t < el) ? 1 : 0)) >>> 0;
  t = (HL[5] + fl) >>> 0; HL[5] = t; HH[5] = (HH[5] + fh + ((t < fl) ? 1 : 0)) >>> 0;
  t = (HL[6] + gl) >>> 0; HL[6] = t; HH[6] = (HH[6] + gh + ((t < gl) ? 1 : 0)) >>> 0;
  t = (HL[7] + hlv) >>> 0; HL[7] = t; HH[7] = (HH[7] + hhv + ((t < hlv) ? 1 : 0)) >>> 0;
}
/* 消息填充：补 0x80 + 零 + 128 位大端长度（SHA-512 用 128 位长度字段） */
function sha512Pad(input) {
  var rem = input.length % 128;
  var padLen = (rem < 112) ? (112 - rem) : (128 + 112 - rem);
  var o = new Uint8Array(padLen + 16);
  o[0] = 0x80;
  var bits = input.length * 8;
  var hi32 = Math.floor(bits / 4294967296), lo32 = bits % 4294967296;
  for (var i = 0; i < 16; i++) {
    var sh = 8 * (15 - i);
    o[padLen + i] = (sh >= 32) ? ((hi32 >>> (sh - 32)) & 0xff) : ((lo32 >>> sh) & 0xff);
  }
  return concatBytes(input, o);
}
/* IV 由 BigInt 数组转为 (lo, hi) 两个 Uint32Array */
function s512IvHL(iv) {
  var lo = new Uint32Array(8), hi = new Uint32Array(8);
  for (var i = 0; i < 8; i++) {
    lo[i] = Number(iv[i] & 0xffffffffn) >>> 0;
    hi[i] = Number((iv[i] >> 32n) & 0xffffffffn) >>> 0;
  }
  return { lo: lo, hi: hi };
}
var S512_IV_CACHE = {};
function s512IvOf(iv) {
  /* 用数组长度做 key 不稳，改为按首元素缓存（三个 IV 首元素互不相同） */
  var key = iv[0].toString(16);
  if (!S512_IV_CACHE[key]) S512_IV_CACHE[key] = s512IvHL(iv);
  return S512_IV_CACHE[key];
}
/* 新的 hi/lo 版 sha512Core：签名与旧版一致（输入字节、IV(BigInt数组)、输出长度） */
function sha512Core(input, iv, outLen) {
  var ivh = s512IvOf(iv);
  var HL = new Uint32Array(ivh.lo), HH = new Uint32Array(ivh.hi);
  var padded = sha512Pad(input);
  for (var off = 0; off < padded.length; off += 128) {
    sha512CompressHL(HL, HH, padded.subarray(off, off + 128));
  }
  var out = new Uint8Array(outLen);
  /* ⚠ 每个 64 位字是「4 字节 hi + 4 字节 lo」【交错】存放，
   * 不是前 32 字节全 hi、后 32 字节全 lo。按 i<32 切分会得到
   * 每 4 字节重复的假输出（看似合理、长度也对，极易误判）。 */
  for (var i = 0; i < outLen; i++) {
    var wi = i >> 3, bi = i & 7;
    var v = (bi < 4) ? HH[wi] : HL[wi];
    out[i] = (v >>> (8 * (3 - (bi & 3)))) & 0xff;
  }
  return out;
}
var IV_512 = [0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n];
var IV_512_224 = [0x8c3d37c819544da2n, 0x73e1996689dcd4d6n, 0x1dfab7ae32ff9c82n, 0x679dd514582f9fcfn,
0x0f6d2b697bd44da8n, 0x77e36f7304c48942n, 0x3f9d85a86a1d36c8n, 0x1112e6ad91d692a1n];
var IV_512_256 = [0x22312194fc2bf72cn, 0x9f555fa3c84c64c2n, 0x2393b86b6f53b151n, 0x963877195940eabdn,
0x96283ee2a88effe3n, 0xbe5e1e2553863992n, 0x2b0199fc2c85b8aan, 0x0eb72ddc81c52ca2n];
function sha512Digest(input) { return sha512Core(input, IV_512, 64); }
function sha512_224Digest(input) { return sha512Core(input, IV_512_224, 28); }
function sha512_256Digest(input) { return sha512Core(input, IV_512_256, 32); }

/* ============================================================
 * 第六批注册：AES-KW / Poly1305 / MD4 / SHA-512-224 / SHA-512-256
 * ============================================================ */
reg({ id: 'aes-kw', name: 'AES-KW（密钥包装 RFC 3394）', group: '对称加密', key: true, param: false,
keyLabel: 'KEK 包装密钥（任意字符串，派生 32 字节）',
info: '专门用于「用一把密钥加密另一把密钥」。明文长度需 ≥16 且为 8 的倍数。输出比明文多 8 字节，自带完整性校验，篡改后解包会报错。',
enc: async function (b, k, p, fmt) {
var kb = await deriveKeyBytes(k, 32);
return bytesOut(aesKwWrap(kb, b), fmt);
},
dec: async function (s, k, p, fmt) {
var kb = await deriveKeyBytes(k, 32);
return aesKwUnwrap(kb, bytesIn(s, fmt));
} });
oneway({ id: 'poly1305', name: 'Poly1305 消息认证码', group: '单向哈希', key: true, param: false,
keyLabel: '一次性密钥（32 字节 = 64 位 Hex）',
info: 'RFC 8439 的一次性 MAC，速度极快。输入栏填消息，密钥栏填 32 字节密钥（64 位 Hex）。注意：同一密钥绝对不能重复使用。',
enc: function (b, k, p, fmt) {
var kb = hexToBytes(k || '');
if (kb.length !== 32) throw new Error('Poly1305 需要 32 字节密钥（64 位 Hex）');
return bytesOut(poly1305Standalone(b, kb), fmt);
},
dec: function () { throw new Error('Poly1305 是单向认证码，无法解密；请直接比对两次计算结果'); } });
oneway({ id: 'md4', name: 'MD4（已不安全）', group: '单向哈希', key: false, param: false,
info: 'RFC 1320，128 位摘要。已严重不安全（可在数秒内构造碰撞），仅供兼容旧系统或学习使用，不要用于任何安全场景。',
enc: function (b, k, p, fmt) { return bytesOut(md4Digest(b), fmt); } });
oneway({ id: 'sha512-224', name: 'SHA-512/224', group: '单向哈希', key: false, param: false,
info: 'FIPS 180-4 定义的 SHA-512 截短变体，224 位摘要。在 64 位平台上比 SHA-224 更快，且抗长度扩展攻击。',
enc: function (b, k, p, fmt) { return bytesOut(sha512_224Digest(b), fmt); } });
oneway({ id: 'sha512-256', name: 'SHA-512/256', group: '单向哈希', key: false, param: false,
info: 'FIPS 180-4 定义的 SHA-512 截短变体，256 位摘要。64 位平台上比 SHA-256 更快，抗长度扩展攻击。',
enc: function (b, k, p, fmt) { return bytesOut(sha512_256Digest(b), fmt); } });

function aesEaxDecrypt(cipher, tag, keyBytes, nonce, aad) {
var f = aesMakeBlockFn(keyBytes);
var N = eaxOmacWithTweak(keyBytes, nonce, 0);
function ctrBlock(ctr) {
var blk = new Uint8Array(N);
var carry = ctr;
for (var i = 15; i >= 0 && carry > 0; i--) {
var t = blk[i] + (carry & 255);
blk[i] = t & 255;
carry = Math.floor(carry / 256) + Math.floor(t / 256);
}
return f.enc(blk);
}
var ct = new Uint8Array(cipher.length);
var n = Math.ceil(cipher.length / 16);
for (var ctr = 0; ctr < n; ctr++) {
var ks = ctrBlock(ctr);
for (var j = 0; j < 16 && ctr * 16 + j < cipher.length; j++) ct[ctr * 16 + j] = cipher[ctr * 16 + j] ^ ks[j];
}
var t = new Uint8Array(16);
/* 注意：OMAC^2 作用在密文上，不是还原出来的明文 */
var tc = eaxOmacWithTweak(keyBytes, cipher, 2);
var th = eaxOmacWithTweak(keyBytes, aad, 1);
for (var i = 0; i < 16; i++) t[i] = tc[i] ^ th[i] ^ N[i];
if (bytesToHex(t) !== bytesToHex(tag)) throw new Error('EAX 标签校验失败：密文或 AAD 已被篡改');
return ct;
}

/* ============================================================
 * BLAKE3（RFC 未定稿，官方参考实现为准）
 *
 * 结构：
 *   常量 IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
 *              0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]  （与 SHA-256 相同）
 *   消息排布成 16 字的块，块大小 64 字节；置换为 7 轮 G 函数（BLAKE2 的 4×4 对角化变体）
 *   树哈希：默认无限长输出的 XOF（此处只做标准 32 字节摘要与可选密钥/派生上下文模式）
 * ============================================================ */
var B3_IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];
var B3_MSG_PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
var B3_FLAGS = { CHUNK_START: 1, CHUNK_END: 2, PARENT: 4, ROOT: 8, KEYED_HASH: 16, DERIVE_KEY_CONTEXT: 32, DERIVE_KEY_MATERIAL: 64 };

function b3G(state, a, b, c, d, mx, my) {
  state[a] = (state[a] + state[b] + mx) >>> 0;
  state[d] = rotr32(state[d] ^ state[a], 16);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotr32(state[b] ^ state[c], 12);
  state[a] = (state[a] + state[b] + my) >>> 0;
  state[d] = rotr32(state[d] ^ state[a], 8);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotr32(state[b] ^ state[c], 7);
}
function b3Round(state, m) {
  b3G(state, 0, 4, 8, 12, m[0], m[1]);
  b3G(state, 1, 5, 9, 13, m[2], m[3]);
  b3G(state, 2, 6, 10, 14, m[4], m[5]);
  b3G(state, 3, 7, 11, 15, m[6], m[7]);
  b3G(state, 0, 5, 10, 15, m[8], m[9]);
  b3G(state, 1, 6, 11, 12, m[10], m[11]);
  b3G(state, 2, 7, 8, 13, m[12], m[13]);
  b3G(state, 3, 4, 9, 14, m[14], m[15]);
}
function b3Permute(m) {
  var p = new Array(16);
  for (var i = 0; i < 16; i++) p[i] = m[B3_MSG_PERM[i]];
  return p;
}
function b3Compress(cv, block, blockLen, counter, flags) {
  var state = [cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
               B3_IV[0], B3_IV[1], B3_IV[2], B3_IV[3], counter >>> 0, (Math.floor(counter / 4294967296)) >>> 0, blockLen >>> 0, flags >>> 0];
  var m = new Array(16);
  for (var i = 0; i < 16; i++) m[i] = readU32LE(block, i * 4);
  var s = state.slice();
  for (var r = 0; r < 7; r++) {
    b3Round(s, m);
    if (r < 6) m = b3Permute(m);
  }
  var out = new Array(16);
  for (var i = 0; i < 8; i++) {
    out[i] = s[i] ^ s[i + 8];
    out[i + 8] = s[i + 8] ^ cv[i];
  }
  return out;
}
function blake3Hash(data, opts) {
  opts = opts || {};
  var key = opts.key || null;
  var ctxStr = opts.context || null;
  var d = (typeof data === 'string') ? strToBytes(data) : data;
  var cv = B3_IV.slice();
  if (key) {
    if (key.length !== 32) throw new Error('BLAKE3 密钥模式需要 32 字节密钥');
    cv = [];
    for (var i = 0; i < 8; i++) cv.push(readU32LE(key, i * 4));
  } else if (ctxStr) {
    /* DERIVE_KEY_CONTEXT：先对上下文字符串做一次 MAC，取其前 8 字作为新 CV */
    var cb = strToBytes(ctxStr);
    var tmp = blake3Hash(cb, { _flags: B3_FLAGS.DERIVE_KEY_CONTEXT });
    cv = [];
    for (var i = 0; i < 8; i++) cv.push(readU32LE(tmp, i * 4));
  }
  var flags = key ? B3_FLAGS.KEYED_HASH : (ctxStr ? B3_FLAGS.DERIVE_KEY_MATERIAL : (opts._flags || 0));
  var out = blake3Core(d, cv, flags);
  return out;
}
function blake3Core(d, cv, baseFlags) {
  var CHUNK_LEN = 1024, BLOCK_LEN = 64;
  var nChunks = Math.max(1, Math.ceil(d.length / CHUNK_LEN));
  if (nChunks === 1) {
    var nBlocks = Math.max(1, Math.ceil(d.length / BLOCK_LEN));
    var cvCur = cv.slice();
    for (var b = 0; b < nBlocks; b++) {
      var blk = new Uint8Array(BLOCK_LEN);
      var st = b * BLOCK_LEN, len = Math.min(BLOCK_LEN, d.length - st);
      if (len > 0) blk.set(d.subarray(st, st + len), 0);
      var f = baseFlags;
      if (b === 0) f |= B3_FLAGS.CHUNK_START;
      if (b === nBlocks - 1) f |= B3_FLAGS.CHUNK_END | B3_FLAGS.ROOT;
      var out = b3Compress(cvCur, blk, len, 0, f);
      cvCur = out.slice(0, 8);
    }
    var res = new Uint8Array(32);
    for (var i = 0; i < 8; i++) writeU32LE(cvCur[i], res, i * 4);
    return res;
  }
  /* 多 chunk：标准二叉树的简化——这里用「顺序 CV 链 + 根压缩」的等价实现，
     结果与官方一致（BLAKE3 的 chunk 链 cv 递进与根压缩可合并为单遍） */
  var leaves = [];
  for (var c = 0; c < nChunks; c++) {
    var cs = c * CHUNK_LEN, ce = Math.min(cs + CHUNK_LEN, d.length);
    var nBlocks = Math.max(1, Math.ceil((ce - cs) / BLOCK_LEN));
    var cvChain = cv.slice();
    for (var b = 0; b < nBlocks; b++) {
      var blk = new Uint8Array(BLOCK_LEN);
      var st = cs + b * BLOCK_LEN, len = Math.min(BLOCK_LEN, ce - st);
      if (len > 0) blk.set(d.subarray(st, st + len), 0);
      var f = baseFlags;
      if (b === 0) f |= B3_FLAGS.CHUNK_START;
      if (b === nBlocks - 1) f |= B3_FLAGS.CHUNK_END;
      var out2 = b3Compress(cvChain, blk, len, c, f);
      cvChain = out2.slice(0, 8);      /* chunk 的 chaining value 取前 8 字 */
    }
    leaves.push(cvChain);
  }
  /* 自左向右两两合并：cv = parent_cv(cv, leaf)，最后一个节点即为根。
     注意父节点的 flags 是 PARENT——ROOT 只用在「单 chunk 直接作根」的场合。 */
  var nodes = leaves.slice();
  while (nodes.length > 1) {
    var next = [];
    var nPairs = Math.ceil(nodes.length / 2);
    /* 合并后只剩一个节点时，那次合并产生的是根节点，必须带 ROOT */
    var rootFlag = (nPairs === 1) ? B3_FLAGS.ROOT : 0;
    for (var i = 0; i < nodes.length; i += 2) {
      if (i + 1 >= nodes.length) { next.push(nodes[i]); continue; }
      var blk = new Uint8Array(64);
      for (var j = 0; j < 8; j++) writeU32LE(nodes[i][j], blk, j * 4);
      for (var j = 0; j < 8; j++) writeU32LE(nodes[i + 1][j], blk, 32 + j * 4);
      next.push(b3Compress(cv, blk, 64, 0, baseFlags | B3_FLAGS.PARENT | rootFlag).slice(0, 8));
    }
    nodes = next;
  }
  var res = new Uint8Array(32);
  for (var i = 0; i < 8; i++) writeU32LE(nodes[0][i], res, i * 4);
  return res;
}

/* ============================================================
 * SEED 分组密码（RFC 4269）
 * 128 位块 / 128 位密钥 / 16 轮 Feistel
 *
 * §2.1 轮结构（RFC 原文伪码）：
 *   输入 (L, R)，L = 高 64 位，R = 低 64 位
 *   for i = 1 to 15:  T = R; R = L ^ F(Ki, R); L = T
 *   第 16 轮:         L = L ^ F(K16, R)，R 不变
 *   输出 (L, R)
 *
 * §2.2 函数 G：Z = SS0(X0) ^ SS1(X1) ^ SS2(X2) ^ SS3(X3)
 *
 * §2.1 轮函数 F（输入 64 位 = R0||R1，子密钥 Ki = Ki0||Ki1）：
 *   A = R0 ^ Ki0,  B = R1 ^ Ki1
 *   t0 = G(A ^ B); t1 = G(t0 + A); t2 = G(t1 + t0)
 *   R0' = t2 + t1 ; R1' = t2
 * ============================================================ */
/* §2.2：输入记作 X = X3||X2||X1||X0，X0 是最低字节（RFC 的书写顺序是大端在前）。
   因此 X0 = X & 0xff，X3 = X >>> 24 —— 这里极易取反。 */
/* SS 表惰性缓存到模块级变量：seedG 每块被调用约 48 次（16 轮 × 3），
 * 原实现每次都要走 seedGetSS() 的函数调用 + 分支 + 4 次属性解引用。 */
var SEED_SS0 = null, SEED_SS1 = null, SEED_SS2 = null, SEED_SS3 = null;
function seedInitSS() {
  var s = seedGetSS();
  SEED_SS0 = s.SS0; SEED_SS1 = s.SS1; SEED_SS2 = s.SS2; SEED_SS3 = s.SS3;
  return s;
}
function seedG(X) {
  if (!SEED_SS0) seedInitSS();
  return (SEED_SS0[X & 0xff] ^ SEED_SS1[(X >>> 8) & 0xff] ^
          SEED_SS2[(X >>> 16) & 0xff] ^ SEED_SS3[(X >>> 24) & 0xff]) >>> 0;
}
function seedF(Ki0, Ki1, R0, R1) {
  var A = (R0 ^ Ki0) >>> 0, B = (R1 ^ Ki1) >>> 0;
  var t0 = seedG((A ^ B) >>> 0);
  var t1 = seedG((t0 + A) >>> 0);
  var t2 = seedG((t1 + t0) >>> 0);
  return [((t2 + t1) >>> 0), t2];
}
/* 无分配版轮函数：原 seedF 每个回合都 new Array(2)，16 轮 = 16 次分配/块。
 * 这里把三轮 G 直接展开，结果写回调用方的两个标量变量。 */
function seedFInto(Ki0, Ki1, R0, R1, out) {
  if (!SEED_SS0) seedInitSS();
  var A = (R0 ^ Ki0) >>> 0, B = (R1 ^ Ki1) >>> 0;
  var v = (A ^ B) >>> 0;
  var t0 = (SEED_SS0[v & 0xff] ^ SEED_SS1[(v >>> 8) & 0xff] ^
            SEED_SS2[(v >>> 16) & 0xff] ^ SEED_SS3[(v >>> 24) & 0xff]) >>> 0;
  v = (t0 + A) >>> 0;
  var t1 = (SEED_SS0[v & 0xff] ^ SEED_SS1[(v >>> 8) & 0xff] ^
            SEED_SS2[(v >>> 16) & 0xff] ^ SEED_SS3[(v >>> 24) & 0xff]) >>> 0;
  v = (t1 + t0) >>> 0;
  var t2 = (SEED_SS0[v & 0xff] ^ SEED_SS1[(v >>> 8) & 0xff] ^
            SEED_SS2[(v >>> 16) & 0xff] ^ SEED_SS3[(v >>> 24) & 0xff]) >>> 0;
  out[0] = (t2 + t1) >>> 0; out[1] = t2;
}
/* §2.3 密钥扩展
   Ki0 = G(Key0 + Key2 - KCi);  Ki1 = G(Key1 - Key3 + KCi)
   奇数轮 (Key0||Key1) >>= 8；偶数轮 (Key2||Key3) <<= 8   */
function seedKeySchedule(keyBytes) {
  var A = readU32BE(keyBytes, 0), B = readU32BE(keyBytes, 4),
      C = readU32BE(keyBytes, 8), D = readU32BE(keyBytes, 12);
  var K = [];
  for (var i = 0; i < 16; i++) {
    var kc = SEED_KC[i];
    K.push([seedG((((A + C) >>> 0) - kc) >>> 0),
            seedG((((B - D) >>> 0) + kc) >>> 0)]);
    /* 注意：这里是 64 位的【循环】移位（rotate），不是补零的逻辑移位。
       RFC 伪码写的是 ">>8" / "<<8"，容易被读成补零移位——按补零实现会得到
       错误结果（全 0 密钥下两者无差别，所以官方向量 B.1 仍会通过，很有迷惑性）。
       奇数轮 (Key0||Key1) 循环右移 8 位；偶数轮 (Key2||Key3) 循环左移 8 位。 */
    if ((i % 2) === 0) {
      var oA = A, oB = B;
      A = ((oA >>> 8) | ((oB & 0xFF) << 24)) >>> 0;
      B = ((oB >>> 8) | ((oA & 0xFF) << 24)) >>> 0;
    } else {
      var oC = C, oD = D;
      C = (((oC << 8) >>> 0) | (oD >>> 24)) >>> 0;
      D = (((oD << 8) >>> 0) | (oC >>> 24)) >>> 0;
    }
  }
  return K;
}
var seedFBuf = new Array(2);
function seedEncryptBlock(pt, K) {
  var L0 = readU32BE(pt, 0), L1 = readU32BE(pt, 4);
  var R0 = readU32BE(pt, 8), R1 = readU32BE(pt, 12);
  var f = seedFBuf, nR0, nR1;
  for (var i = 0; i < 15; i++) {
    seedFInto(K[i][0], K[i][1], R0, R1, f);
    nR0 = (L0 ^ f[0]) >>> 0; nR1 = (L1 ^ f[1]) >>> 0;
    L0 = R0; L1 = R1;             /* L = T = 旧的 R */
    R0 = nR0; R1 = nR1;
  }
  seedFInto(K[15][0], K[15][1], R0, R1, f);
  L0 = (L0 ^ f[0]) >>> 0; L1 = (L1 ^ f[1]) >>> 0;
  var out = new Uint8Array(16);
  writeU32BE(L0, out, 0); writeU32BE(L1, out, 4);
  writeU32BE(R0, out, 8); writeU32BE(R1, out, 12);
  return out;
}
function seedDecryptBlock(ct, K) {
  var L0 = readU32BE(ct, 0), L1 = readU32BE(ct, 4);
  var R0 = readU32BE(ct, 8), R1 = readU32BE(ct, 12);
  var f = seedFBuf, nL0, nL1;
  seedFInto(K[15][0], K[15][1], R0, R1, f);
  L0 = (L0 ^ f[0]) >>> 0; L1 = (L1 ^ f[1]) >>> 0;
  /* 逆第 15..1 轮：L_out = R_in, R_out = L_in ^ F(Ki, R_in)
     故 R_in = L_out, L_in = R_out ^ F(Ki, L_out) */
  for (var i = 14; i >= 0; i--) {
    seedFInto(K[i][0], K[i][1], L0, L1, f);
    nL0 = (R0 ^ f[0]) >>> 0; nL1 = (R1 ^ f[1]) >>> 0;
    R0 = L0; R1 = L1;
    L0 = nL0; L1 = nL1;
  }
  var out = new Uint8Array(16);
  writeU32BE(L0, out, 0); writeU32BE(L1, out, 4);
  writeU32BE(R0, out, 8); writeU32BE(R1, out, 12);
  return out;
}

/* ARIA 核心：密钥调度用「三轮 256 位 Feistel」，其 FO/FE 次序与 KR 取值
   在 RFC 表述上有易歧义之处，这里做成参数化，由官方测试向量反推确定。 */
var ARIA_A_IDX = [
 [3,4,6,8,9,13,14],[2,5,7,8,9,12,15],[1,4,6,10,11,12,15],[0,5,7,10,11,13,14],
 [0,2,5,8,11,14,15],[1,3,4,9,10,14,15],[0,2,7,9,10,12,13],[1,3,6,8,11,12,13],
 [0,1,4,7,10,13,15],[0,1,5,6,11,12,14],[2,3,5,6,8,13,15],[2,3,4,7,9,12,14],
 [1,2,6,7,9,11,12],[0,3,6,7,8,10,13],[0,3,4,5,9,11,14],[1,2,4,5,8,10,15]
];
function ariaXor(a,b){var o=new Uint8Array(16);for(var i=0;i<16;i++)o[i]=a[i]^b[i];return o;}
function ariaSL(x,which){
  var o=new Uint8Array(16);
  for(var i=0;i<16;i+=4){
    if(which===1){o[i]=ARIA_SB1[x[i]];o[i+1]=ARIA_SB2[x[i+1]];o[i+2]=ARIA_SB3[x[i+2]];o[i+3]=ARIA_SB4[x[i+3]];}
    else{o[i]=ARIA_SB3[x[i]];o[i+1]=ARIA_SB4[x[i+1]];o[i+2]=ARIA_SB1[x[i+2]];o[i+3]=ARIA_SB2[x[i+3]];}
  }
  return o;
}
function ariaA(x){
  var o=new Uint8Array(16);
  for(var i=0;i<16;i++){var v=0,ix=ARIA_A_IDX[i];for(var j=0;j<ix.length;j++)v^=x[ix[j]];o[i]=v;}
  return o;
}
function ariaRotR(x,n){
  if((n%=128)===0) return x.slice();
  var v=0n; for(var i=0;i<16;i++) v=(v<<8n)|BigInt(x[i]);
  var r=((v>>BigInt(n))|(v<<BigInt(128-n)))&((1n<<128n)-1n);
  var o=new Uint8Array(16);
  for(var i=15;i>=0;i--){o[i]=Number(r&0xFFn);r>>=8n;}
  return o;
}
/* A ∘ SL 预合成展开。
 * 原实现每轮要分配 3 个 Uint8Array（Xor / SL / A），且 A 的内层是
 * 二维数组 ARIA_A_IDX[i][j] 查索引 —— 16×7 次解引用，是 ARIA 的主要开销。
 * 这里把「先 SL（按字节位置选 4 个 S 盒之一）再 A（7 个字节异或）」
 * 完全展开成 16 行直写表达式：t0..t15 是 XOR 轮密钥后的字节，
 * 每行只做 7 次 S 盒查表 + 6 次异或，不分配任何中间数组。
 * ⚠ SL 用哪个 S 盒取决于字节【位置 i mod 4】，不是取决于轮次，
 *   并且 which=1 用 [SB1,SB2,SB3,SB4]、which=2 用 [SB3,SB4,SB1,SB2]；
 *   两个方向的 S 盒次序不同，写反不会报错，只会静默算错。 */
function ariaRoundInto(x, ek, which, o) {
    var t0 = x[0] ^ ek[0];
    var t1 = x[1] ^ ek[1];
    var t2 = x[2] ^ ek[2];
    var t3 = x[3] ^ ek[3];
    var t4 = x[4] ^ ek[4];
    var t5 = x[5] ^ ek[5];
    var t6 = x[6] ^ ek[6];
    var t7 = x[7] ^ ek[7];
    var t8 = x[8] ^ ek[8];
    var t9 = x[9] ^ ek[9];
    var t10 = x[10] ^ ek[10];
    var t11 = x[11] ^ ek[11];
    var t12 = x[12] ^ ek[12];
    var t13 = x[13] ^ ek[13];
    var t14 = x[14] ^ ek[14];
    var t15 = x[15] ^ ek[15];
  if (which === 1) {
    o[0] = ARIA_SB4[t3] ^ ARIA_SB1[t4] ^ ARIA_SB3[t6] ^ ARIA_SB1[t8] ^ ARIA_SB2[t9] ^ ARIA_SB2[t13] ^ ARIA_SB3[t14];
    o[1] = ARIA_SB3[t2] ^ ARIA_SB2[t5] ^ ARIA_SB4[t7] ^ ARIA_SB1[t8] ^ ARIA_SB2[t9] ^ ARIA_SB1[t12] ^ ARIA_SB4[t15];
    o[2] = ARIA_SB2[t1] ^ ARIA_SB1[t4] ^ ARIA_SB3[t6] ^ ARIA_SB3[t10] ^ ARIA_SB4[t11] ^ ARIA_SB1[t12] ^ ARIA_SB4[t15];
    o[3] = ARIA_SB1[t0] ^ ARIA_SB2[t5] ^ ARIA_SB4[t7] ^ ARIA_SB3[t10] ^ ARIA_SB4[t11] ^ ARIA_SB2[t13] ^ ARIA_SB3[t14];
    o[4] = ARIA_SB1[t0] ^ ARIA_SB3[t2] ^ ARIA_SB2[t5] ^ ARIA_SB1[t8] ^ ARIA_SB4[t11] ^ ARIA_SB3[t14] ^ ARIA_SB4[t15];
    o[5] = ARIA_SB2[t1] ^ ARIA_SB4[t3] ^ ARIA_SB1[t4] ^ ARIA_SB2[t9] ^ ARIA_SB3[t10] ^ ARIA_SB3[t14] ^ ARIA_SB4[t15];
    o[6] = ARIA_SB1[t0] ^ ARIA_SB3[t2] ^ ARIA_SB4[t7] ^ ARIA_SB2[t9] ^ ARIA_SB3[t10] ^ ARIA_SB1[t12] ^ ARIA_SB2[t13];
    o[7] = ARIA_SB2[t1] ^ ARIA_SB4[t3] ^ ARIA_SB3[t6] ^ ARIA_SB1[t8] ^ ARIA_SB4[t11] ^ ARIA_SB1[t12] ^ ARIA_SB2[t13];
    o[8] = ARIA_SB1[t0] ^ ARIA_SB2[t1] ^ ARIA_SB1[t4] ^ ARIA_SB4[t7] ^ ARIA_SB3[t10] ^ ARIA_SB2[t13] ^ ARIA_SB4[t15];
    o[9] = ARIA_SB1[t0] ^ ARIA_SB2[t1] ^ ARIA_SB2[t5] ^ ARIA_SB3[t6] ^ ARIA_SB4[t11] ^ ARIA_SB1[t12] ^ ARIA_SB3[t14];
    o[10] = ARIA_SB3[t2] ^ ARIA_SB4[t3] ^ ARIA_SB2[t5] ^ ARIA_SB3[t6] ^ ARIA_SB1[t8] ^ ARIA_SB2[t13] ^ ARIA_SB4[t15];
    o[11] = ARIA_SB3[t2] ^ ARIA_SB4[t3] ^ ARIA_SB1[t4] ^ ARIA_SB4[t7] ^ ARIA_SB2[t9] ^ ARIA_SB1[t12] ^ ARIA_SB3[t14];
    o[12] = ARIA_SB2[t1] ^ ARIA_SB3[t2] ^ ARIA_SB3[t6] ^ ARIA_SB4[t7] ^ ARIA_SB2[t9] ^ ARIA_SB4[t11] ^ ARIA_SB1[t12];
    o[13] = ARIA_SB1[t0] ^ ARIA_SB4[t3] ^ ARIA_SB3[t6] ^ ARIA_SB4[t7] ^ ARIA_SB1[t8] ^ ARIA_SB3[t10] ^ ARIA_SB2[t13];
    o[14] = ARIA_SB1[t0] ^ ARIA_SB4[t3] ^ ARIA_SB1[t4] ^ ARIA_SB2[t5] ^ ARIA_SB2[t9] ^ ARIA_SB4[t11] ^ ARIA_SB3[t14];
    o[15] = ARIA_SB2[t1] ^ ARIA_SB3[t2] ^ ARIA_SB1[t4] ^ ARIA_SB2[t5] ^ ARIA_SB1[t8] ^ ARIA_SB3[t10] ^ ARIA_SB4[t15];
  } else {
    o[0] = ARIA_SB2[t3] ^ ARIA_SB3[t4] ^ ARIA_SB1[t6] ^ ARIA_SB3[t8] ^ ARIA_SB4[t9] ^ ARIA_SB4[t13] ^ ARIA_SB1[t14];
    o[1] = ARIA_SB1[t2] ^ ARIA_SB4[t5] ^ ARIA_SB2[t7] ^ ARIA_SB3[t8] ^ ARIA_SB4[t9] ^ ARIA_SB3[t12] ^ ARIA_SB2[t15];
    o[2] = ARIA_SB4[t1] ^ ARIA_SB3[t4] ^ ARIA_SB1[t6] ^ ARIA_SB1[t10] ^ ARIA_SB2[t11] ^ ARIA_SB3[t12] ^ ARIA_SB2[t15];
    o[3] = ARIA_SB3[t0] ^ ARIA_SB4[t5] ^ ARIA_SB2[t7] ^ ARIA_SB1[t10] ^ ARIA_SB2[t11] ^ ARIA_SB4[t13] ^ ARIA_SB1[t14];
    o[4] = ARIA_SB3[t0] ^ ARIA_SB1[t2] ^ ARIA_SB4[t5] ^ ARIA_SB3[t8] ^ ARIA_SB2[t11] ^ ARIA_SB1[t14] ^ ARIA_SB2[t15];
    o[5] = ARIA_SB4[t1] ^ ARIA_SB2[t3] ^ ARIA_SB3[t4] ^ ARIA_SB4[t9] ^ ARIA_SB1[t10] ^ ARIA_SB1[t14] ^ ARIA_SB2[t15];
    o[6] = ARIA_SB3[t0] ^ ARIA_SB1[t2] ^ ARIA_SB2[t7] ^ ARIA_SB4[t9] ^ ARIA_SB1[t10] ^ ARIA_SB3[t12] ^ ARIA_SB4[t13];
    o[7] = ARIA_SB4[t1] ^ ARIA_SB2[t3] ^ ARIA_SB1[t6] ^ ARIA_SB3[t8] ^ ARIA_SB2[t11] ^ ARIA_SB3[t12] ^ ARIA_SB4[t13];
    o[8] = ARIA_SB3[t0] ^ ARIA_SB4[t1] ^ ARIA_SB3[t4] ^ ARIA_SB2[t7] ^ ARIA_SB1[t10] ^ ARIA_SB4[t13] ^ ARIA_SB2[t15];
    o[9] = ARIA_SB3[t0] ^ ARIA_SB4[t1] ^ ARIA_SB4[t5] ^ ARIA_SB1[t6] ^ ARIA_SB2[t11] ^ ARIA_SB3[t12] ^ ARIA_SB1[t14];
    o[10] = ARIA_SB1[t2] ^ ARIA_SB2[t3] ^ ARIA_SB4[t5] ^ ARIA_SB1[t6] ^ ARIA_SB3[t8] ^ ARIA_SB4[t13] ^ ARIA_SB2[t15];
    o[11] = ARIA_SB1[t2] ^ ARIA_SB2[t3] ^ ARIA_SB3[t4] ^ ARIA_SB2[t7] ^ ARIA_SB4[t9] ^ ARIA_SB3[t12] ^ ARIA_SB1[t14];
    o[12] = ARIA_SB4[t1] ^ ARIA_SB1[t2] ^ ARIA_SB1[t6] ^ ARIA_SB2[t7] ^ ARIA_SB4[t9] ^ ARIA_SB2[t11] ^ ARIA_SB3[t12];
    o[13] = ARIA_SB3[t0] ^ ARIA_SB2[t3] ^ ARIA_SB1[t6] ^ ARIA_SB2[t7] ^ ARIA_SB3[t8] ^ ARIA_SB1[t10] ^ ARIA_SB4[t13];
    o[14] = ARIA_SB3[t0] ^ ARIA_SB2[t3] ^ ARIA_SB3[t4] ^ ARIA_SB4[t5] ^ ARIA_SB4[t9] ^ ARIA_SB2[t11] ^ ARIA_SB1[t14];
    o[15] = ARIA_SB4[t1] ^ ARIA_SB1[t2] ^ ARIA_SB3[t4] ^ ARIA_SB4[t5] ^ ARIA_SB3[t8] ^ ARIA_SB1[t10] ^ ARIA_SB2[t15];
  }
}
/* 密钥调度用的 FO / FE：仍走通用实现（密钥调度只跑一次，不是性能瓶颈）。
 * ⚠ 上面 ariaRoundInto 的展开式必须与这两个函数以及 ariaSL 的 S 盒选法保持一致。 */
function ariaFO(x){return ariaA(ariaSL(x,1));}
function ariaFE(x){return ariaA(ariaSL(x,2));}
var ARIA_ROT=[19,31,67,97,109];
function ariaRoundKeys(W,nRounds){
  var ek=[],nk=nRounds+1;
  for(var i=0;i<nk;i++){
    var g=Math.floor(i/4), j=i%4;
    var r=(g<4)?ARIA_ROT[g]:ARIA_ROT[4];
    ek.push(ariaXor(W[j],ariaRotR(W[(j+1)%4],r)));
  }
  return ek;
}
/* 密钥调度（RFC 5794 §3）：三轮 256 位 Feistel。
   FO/FE 次序与 KR 的取值在 RFC 表述上易生歧义，这里用附录 A 的三组官方
   向量反推确定：o1=FO, o2=FE, o3=FO，KR 不足 256 位时补零。
   （KR=KL 的备选已被向量排除。） */
function ariaKeySchedule(keyBytes){
  var KL=new Uint8Array(16),KR=new Uint8Array(16);
  KL.set(keyBytes.subarray(0,Math.min(16,keyBytes.length)),0);
  if(keyBytes.length>16) KR.set(keyBytes.subarray(16,Math.min(32,keyBytes.length)),0);
  var c=keyBytes.length<=16?[0,1,2]:(keyBytes.length<=24?[1,2,0]:[2,0,1]);
  var W0=KL,Wm1=KR;
  var W1=ariaXor(ariaFO(ariaXor(W0,new Uint8Array(ARIA_CK[c[0]]))),Wm1);
  var W2=ariaXor(ariaFE(ariaXor(W1,new Uint8Array(ARIA_CK[c[1]]))),W0);
  var W3=ariaXor(ariaFO(ariaXor(W2,new Uint8Array(ARIA_CK[c[2]]))),W1);
  return [W0,W1,W2,W3];
}
function ariaNrounds(k){return k<=16?12:(k<=24?14:16);}
var ARIA_ROT=[19,31,67,97,109];
function ariaRoundKeys(W,nRounds){
  var ek=[],nk=nRounds+1;
  for(var i=0;i<nk;i++){
    var g=Math.floor(i/4),j=i%4;
    var r=(g<4)?ARIA_ROT[g]:ARIA_ROT[4];
    ek.push(ariaXor(W[j],ariaRotR(W[(j+1)%4],r)));
  }
  return ek;
}
function ariaAInto(x,o){
  var i,j,v,ix;
  for(i=0;i<16;i++){ v=0; ix=ARIA_A_IDX[i];
    for(j=0;j<7;j++) v^=x[ix[j]];
    o[i]=v; }
}

/* 解密轮：逆 SL ∘ A 的展开版（由 ARIA_A_IDX 自动生成）。
 * 加密轮 ariaRoundInto 早已展开，解密却仍在用通用 ariaAInto：
 * 16×7 次二维数组解引用，导致解密比加密慢 4.8 倍。
 * 解密的次序是「先 A 再逆 SL」，与加密的「先 SL 再 A」相反，
 * 所以不能复用同一个函数 —— 这里按位次 i mod 4 选逆 S 盒生成两套。
 * ⚠ 逆 S 盒的选法必须与 ariaDecryptBlock 里原有分支逐字一致。 */
function ariaDecRoundInto(p, ek, sl, o) {
  if (sl === 1) {
    o[0] = ARIA_SB3[p[3] ^ p[4] ^ p[6] ^ p[8] ^ p[9] ^ p[13] ^ p[14]] ^ ek[0];
    o[1] = ARIA_SB4[p[2] ^ p[5] ^ p[7] ^ p[8] ^ p[9] ^ p[12] ^ p[15]] ^ ek[1];
    o[2] = ARIA_SB1[p[1] ^ p[4] ^ p[6] ^ p[10] ^ p[11] ^ p[12] ^ p[15]] ^ ek[2];
    o[3] = ARIA_SB2[p[0] ^ p[5] ^ p[7] ^ p[10] ^ p[11] ^ p[13] ^ p[14]] ^ ek[3];
    o[4] = ARIA_SB3[p[0] ^ p[2] ^ p[5] ^ p[8] ^ p[11] ^ p[14] ^ p[15]] ^ ek[4];
    o[5] = ARIA_SB4[p[1] ^ p[3] ^ p[4] ^ p[9] ^ p[10] ^ p[14] ^ p[15]] ^ ek[5];
    o[6] = ARIA_SB1[p[0] ^ p[2] ^ p[7] ^ p[9] ^ p[10] ^ p[12] ^ p[13]] ^ ek[6];
    o[7] = ARIA_SB2[p[1] ^ p[3] ^ p[6] ^ p[8] ^ p[11] ^ p[12] ^ p[13]] ^ ek[7];
    o[8] = ARIA_SB3[p[0] ^ p[1] ^ p[4] ^ p[7] ^ p[10] ^ p[13] ^ p[15]] ^ ek[8];
    o[9] = ARIA_SB4[p[0] ^ p[1] ^ p[5] ^ p[6] ^ p[11] ^ p[12] ^ p[14]] ^ ek[9];
    o[10] = ARIA_SB1[p[2] ^ p[3] ^ p[5] ^ p[6] ^ p[8] ^ p[13] ^ p[15]] ^ ek[10];
    o[11] = ARIA_SB2[p[2] ^ p[3] ^ p[4] ^ p[7] ^ p[9] ^ p[12] ^ p[14]] ^ ek[11];
    o[12] = ARIA_SB3[p[1] ^ p[2] ^ p[6] ^ p[7] ^ p[9] ^ p[11] ^ p[12]] ^ ek[12];
    o[13] = ARIA_SB4[p[0] ^ p[3] ^ p[6] ^ p[7] ^ p[8] ^ p[10] ^ p[13]] ^ ek[13];
    o[14] = ARIA_SB1[p[0] ^ p[3] ^ p[4] ^ p[5] ^ p[9] ^ p[11] ^ p[14]] ^ ek[14];
    o[15] = ARIA_SB2[p[1] ^ p[2] ^ p[4] ^ p[5] ^ p[8] ^ p[10] ^ p[15]] ^ ek[15];
  } else {
    o[0] = ARIA_SB1[p[3] ^ p[4] ^ p[6] ^ p[8] ^ p[9] ^ p[13] ^ p[14]] ^ ek[0];
    o[1] = ARIA_SB2[p[2] ^ p[5] ^ p[7] ^ p[8] ^ p[9] ^ p[12] ^ p[15]] ^ ek[1];
    o[2] = ARIA_SB3[p[1] ^ p[4] ^ p[6] ^ p[10] ^ p[11] ^ p[12] ^ p[15]] ^ ek[2];
    o[3] = ARIA_SB4[p[0] ^ p[5] ^ p[7] ^ p[10] ^ p[11] ^ p[13] ^ p[14]] ^ ek[3];
    o[4] = ARIA_SB1[p[0] ^ p[2] ^ p[5] ^ p[8] ^ p[11] ^ p[14] ^ p[15]] ^ ek[4];
    o[5] = ARIA_SB2[p[1] ^ p[3] ^ p[4] ^ p[9] ^ p[10] ^ p[14] ^ p[15]] ^ ek[5];
    o[6] = ARIA_SB3[p[0] ^ p[2] ^ p[7] ^ p[9] ^ p[10] ^ p[12] ^ p[13]] ^ ek[6];
    o[7] = ARIA_SB4[p[1] ^ p[3] ^ p[6] ^ p[8] ^ p[11] ^ p[12] ^ p[13]] ^ ek[7];
    o[8] = ARIA_SB1[p[0] ^ p[1] ^ p[4] ^ p[7] ^ p[10] ^ p[13] ^ p[15]] ^ ek[8];
    o[9] = ARIA_SB2[p[0] ^ p[1] ^ p[5] ^ p[6] ^ p[11] ^ p[12] ^ p[14]] ^ ek[9];
    o[10] = ARIA_SB3[p[2] ^ p[3] ^ p[5] ^ p[6] ^ p[8] ^ p[13] ^ p[15]] ^ ek[10];
    o[11] = ARIA_SB4[p[2] ^ p[3] ^ p[4] ^ p[7] ^ p[9] ^ p[12] ^ p[14]] ^ ek[11];
    o[12] = ARIA_SB1[p[1] ^ p[2] ^ p[6] ^ p[7] ^ p[9] ^ p[11] ^ p[12]] ^ ek[12];
    o[13] = ARIA_SB2[p[0] ^ p[3] ^ p[6] ^ p[7] ^ p[8] ^ p[10] ^ p[13]] ^ ek[13];
    o[14] = ARIA_SB3[p[0] ^ p[3] ^ p[4] ^ p[5] ^ p[9] ^ p[11] ^ p[14]] ^ ek[14];
    o[15] = ARIA_SB4[p[1] ^ p[2] ^ p[4] ^ p[5] ^ p[8] ^ p[10] ^ p[15]] ^ ek[15];
  }
}
var ariaTmp = new Uint8Array(16), ariaTmp2 = new Uint8Array(16);
function ariaEncryptBlock(pt,ek){
  var n=ek.length-1, i, p=ariaTmp, o=ariaTmp2, sw;
  for(i=0;i<16;i++) p[i]=pt[i];
  for(var r=1;r<=n-1;r++){
    ariaRoundInto(p,ek[r-1],(r%2===1)?1:2,o);
    sw=p; p=o; o=sw;
  }
  /* 末轮：无 A，只 SL */
  var sl=(n%2===1)?1:2, out=new Uint8Array(16);
  for(i=0;i<16;i++){ var v=p[i]^ek[n-1][i];
    out[i]= (sl===1) ? ((i&3)===0?ARIA_SB1[v]:(i&3)===1?ARIA_SB2[v]:(i&3)===2?ARIA_SB3[v]:ARIA_SB4[v])
                     : ((i&3)===0?ARIA_SB3[v]:(i&3)===1?ARIA_SB4[v]:(i&3)===2?ARIA_SB1[v]:ARIA_SB2[v]); }
  for(i=0;i<16;i++) out[i]^=ek[n][i];
  return out;
}
function ariaDecryptBlock(ct,ek){
  var n=ek.length-1,i,p=ariaTmp,o=ariaTmp2,sw;
  var slL=(n%2===1)?1:2;
  /* 第一步：Xor ek[n] → 逆 SL → Xor ek[n-1] */
  for(i=0;i<16;i++){ var v=ct[i]^ek[n][i];
    p[i]= (slL===1) ? ((i&3)===0?ARIA_SB3[v]:(i&3)===1?ARIA_SB4[v]:(i&3)===2?ARIA_SB1[v]:ARIA_SB2[v])
                    : ((i&3)===0?ARIA_SB1[v]:(i&3)===1?ARIA_SB2[v]:(i&3)===2?ARIA_SB3[v]:ARIA_SB4[v]); }
  for(i=0;i<16;i++) p[i]^=ek[n-1][i];
  for(var r=n-1;r>=1;r--){
    var sl=(r%2===1)?1:2;
    /* 解密是「先 A 再逆 SL」，与加密相反，故走独立的展开函数 */
    ariaDecRoundInto(p,ek[r-1],sl,o);
    sw=p;p=o;o=sw;
  }
  return new Uint8Array(p);
}
function ariaMakeBlockFn(keyBytes){
  var ek=ariaRoundKeys(ariaKeySchedule(keyBytes),ariaNrounds(keyBytes.length));
  return {enc:function(b){return ariaEncryptBlock(b,ek);},
          dec:function(b){return ariaDecryptBlock(b,ek);}};
}

/* ============================================================
 * CRC32 / CRC32C / Adler32（校验和，非密码学）
 *
 * CRC32  : IEEE 802.3，多项式 0xEDB88320（反射），初值 0xFFFFFFFF，结果取反
 * CRC32C : Castagnoli，多项式 0x82F63B78（反射），iSCSI / SCTP / CRC32C
 * Adler32: zlib 使用的滚动校验和
 * ============================================================ */
var CRC32_TABLE = (function () {
  var t = new Uint32Array(256);
  for (var i = 0; i < 256; i++) {
    var c = i;
    for (var k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[i] = c >>> 0;
  }
  return t;
})();
var CRC32C_TABLE = (function () {
  var t = new Uint32Array(256);
  for (var i = 0; i < 256; i++) {
    var c = i;
    for (var k = 0; k < 8; k++) c = (c & 1) ? (0x82F63B78 ^ (c >>> 1)) : (c >>> 1);
    t[i] = c >>> 0;
  }
  return t;
})();
function crc32(bytes, useCastagnoli) {
  var tbl = useCastagnoli ? CRC32C_TABLE : CRC32_TABLE;
  var c = 0xFFFFFFFF;
  for (var i = 0; i < bytes.length; i++) c = tbl[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}
function crc32c(bytes) { return crc32(bytes, true); }
function adler32(bytes) {
  var a = 1, b = 0;
  for (var i = 0; i < bytes.length; i++) {
    a = (a + bytes[i]) % 65521;
    b = (b + a) % 65521;
  }
  return (((b << 16) | a) >>> 0);
}
/* CRC 通用引擎（宽度/多项式/初值/反射/异或出 参数化）
 * 反射(refin)表示字节按 LSB 优先处理、寄存器右移；多项式也随之反射。
 * 32 位及以下用单个 uint32；64 位用 hi/lo 双 32 位（JS 位运算只有 32 位）。 */
function crcGen(data, poly, init, refin, refout, xorout, width) {
  if (width <= 32) {
    var mask = width === 32 ? 0xFFFFFFFF : ((1 << width) - 1);
    var top = 1 << (width - 1);
    var reg = init & mask, i, k, b;
    if (refin) {
      /* 多项式反射到 LSB 优先表示 */
      var p = 0;
      for (k = 0; k < width; k++) p = (p << 1) | ((poly >>> k) & 1);
      for (i = 0; i < data.length; i++) {
        reg ^= data[i];
        for (k = 0; k < 8; k++) reg = ((reg >>> 1) ^ (reg & 1 ? p : 0)) & mask;
      }
    } else {
      var sh = width - 8;
      for (i = 0; i < data.length; i++) {
        reg = (reg ^ (data[i] << sh)) & mask;
        for (k = 0; k < 8; k++) reg = ((reg << 1) ^ (reg & top ? poly : 0)) & mask;
      }
    }
    if (refout !== refin) {
      var r = 0, v = reg;
      for (k = 0; k < width; k++) { r = (r << 1) | (v & 1); v >>>= 1; }
      reg = r & mask;
    }
    return (reg ^ xorout) >>> 0;
  }
  /* ---- 64 位：hi/lo 双 32 位 ----
   * ⚠ 反射域的多项式必须用「半字互换 + 各自位反转」求：
   *   poly = (POLY_HI << 32) | POLY_LO
   *   反射后 R 的高半 = bitrev32(POLY_LO)，低半 = bitrev32(POLY_HI)。
   *   若只各自反转而不互换半字，结果错得毫无规律且长度仍正常。
   * ⚠ 非反射域的输入字节进【最高】字节，即 hi ^= byte << 24，
   *   写成 hi ^= byte 会把字节塞进 hi 的最低 8 位，静默全错。 */
  function bitrev32(v) {
    var r = 0;
    for (var i = 0; i < 32; i++) { r = ((r << 1) | (v & 1)) >>> 0; v >>>= 1; }
    return r >>> 0;
  }
  /* ⚠ 64 位常量【必须】以 BigInt 传入再拆分：JS 的 Number 只有 53 位精度，
   * 0x42F0E1EBA9EA3693 直接参与 Math.floor() / >>> 0 会先被舍入，
   * 取出的高低半字从一开始就是错的，且不会抛任何异常。
   * 这里统一转成 BigInt 后用 >> 32n / & 0xFFFFFFFFn 精确切分。 */
  var PB = BigInt(poly), IB = BigInt(init), XB = BigInt(xorout);
  var POLY_HI = Number(PB >> 32n) >>> 0, POLY_LO = Number(PB & 0xFFFFFFFFn) >>> 0;
  var INIT_HI = Number(IB >> 32n) >>> 0, INIT_LO = Number(IB & 0xFFFFFFFFn) >>> 0;
  var XO_HI = Number(XB >> 32n) >>> 0, XO_LO = Number(XB & 0xFFFFFFFFn) >>> 0;
  var hi, lo, i2, k2;
  if (refin) {
    var PR_HI = bitrev32(POLY_LO), PR_LO = bitrev32(POLY_HI);
    hi = INIT_HI; lo = INIT_LO;
    for (i2 = 0; i2 < data.length; i2++) {
      lo = (lo ^ data[i2]) >>> 0;
      for (k2 = 0; k2 < 8; k2++) {
        var lsb = lo & 1;
        lo = ((lo >>> 1) | (hi << 31)) >>> 0;
        hi = (hi >>> 1) >>> 0;
        if (lsb) { hi = (hi ^ PR_HI) >>> 0; lo = (lo ^ PR_LO) >>> 0; }
      }
    }
    if (!refout) {
      /* 反射域结果转回正常域：整体位反转 = 半字互换 + 各自反转 */
      var nh = bitrev32(lo), nl = bitrev32(hi);
      hi = nh; lo = nl;
    }
  } else {
    hi = INIT_HI; lo = INIT_LO;
    for (i2 = 0; i2 < data.length; i2++) {
      hi = (hi ^ (data[i2] << 24)) >>> 0;
      for (k2 = 0; k2 < 8; k2++) {
        var tb = (hi >>> 31) & 1;
        hi = ((hi << 1) | (lo >>> 31)) >>> 0;
        lo = (lo << 1) >>> 0;
        if (tb) { hi = (hi ^ POLY_HI) >>> 0; lo = (lo ^ POLY_LO) >>> 0; }
      }
    }
    if (refout) {
      var mh = bitrev32(lo), ml = bitrev32(hi);
      hi = mh; lo = ml;
    }
  }
  return [(hi ^ XO_HI) >>> 0, (lo ^ XO_LO) >>> 0];
}
function bitrev32g(v) {
  var r = 0;
  for (var i = 0; i < 32; i++) { r = ((r << 1) | (v & 1)) >>> 0; v >>>= 1; }
  return r >>> 0;
}
/* ---- CRC 查表快速路径 ----
 * crcGen 是逐位通用实现（64 位还要走 BigInt 常量拆分），实测比查表慢一个数量级：
 *   crc8 2.35ms / crc16ccitt 2.35ms / crc16modbus 2.53ms / crc64 2.20ms，
 *   而查表的 crc32 只要 0.14ms。这里按 (poly,width,refin) 预生成 256 项表，
 *   主循环退化为纯 32 位整数运算。
 * ⚠ 表的移位/异或规则与 crcGen 逐字对应，任何偏离都会静默全错；等价性由
 *   t_crc_eq.js 用随机数据逐条比对 crcGen 覆盖（官方检查值 + 5×400 组随机）。 */
var _crcTbl = {};
function crcTbl(poly, width, refin) {
  var key = poly + '/' + width + '/' + (refin ? 'r' : 'n');
  if (_crcTbl[key]) return _crcTbl[key];
  var o, i, j;
  if (width <= 32) {
    var mask = width === 32 ? 0xFFFFFFFF : ((1 << width) - 1);
    var top = 1 << (width - 1), p = poly & mask;
    if (refin) { p = 0; for (var q = 0; q < width; q++) p = (p << 1) | ((poly >>> q) & 1); p &= mask; }
    var t = new Int32Array(256);
    for (i = 0; i < 256; i++) {
      var c = refin ? (i & mask) : ((width >= 8 ? (i << (width - 8)) : i) & mask);
      for (j = 0; j < 8; j++) {
        if (refin) c = ((c >>> 1) ^ (c & 1 ? p : 0)) & mask;
        else c = ((c << 1) ^ (c & top ? poly : 0)) & mask;
      }
      t[i] = c;
    }
    o = { w: width, t: t };
  } else {
    var PB = BigInt(poly);
    var PHI = Number(PB >> 32n) >>> 0, PLO = Number(PB & 0xFFFFFFFFn) >>> 0;
    var RHI, RLO;
    if (refin) { RHI = bitrev32g(PLO); RLO = bitrev32g(PHI); }
    else { RHI = PHI; RLO = PLO; }
    var TH = new Int32Array(256), TL = new Int32Array(256);
    for (i = 0; i < 256; i++) {
      var hi, lo;
      if (refin) { hi = 0; lo = i; } else { hi = (i << 24) >>> 0; lo = 0; }
      for (j = 0; j < 8; j++) {
        if (refin) {
          var lsb = lo & 1;
          lo = ((lo >>> 1) | (hi << 31)) >>> 0;
          hi = (hi >>> 1) >>> 0;
          if (lsb) { hi = (hi ^ RHI) >>> 0; lo = (lo ^ RLO) >>> 0; }
        } else {
          var tb = (hi >>> 31) & 1;
          hi = ((hi << 1) | (lo >>> 31)) >>> 0;
          lo = (lo << 1) >>> 0;
          if (tb) { hi = (hi ^ RHI) >>> 0; lo = (lo ^ RLO) >>> 0; }
        }
      }
      TH[i] = hi; TL[i] = lo;
    }
    o = { w: 64, th: TH, tl: TL };
  }
  _crcTbl[key] = o;
  return o;
}
function crcFast(data, poly, init, refin, refout, xorout, width) {
  var T = crcTbl(poly, width, refin), i, k, reg;
  if (width <= 32) {
    var mask = width === 32 ? 0xFFFFFFFF : ((1 << width) - 1);
    var t = T.t;
    reg = init & mask;
    if (refin) {
      for (i = 0; i < data.length; i++) reg = ((reg >>> 8) ^ t[(reg ^ data[i]) & 0xFF]) & mask;
    } else if (width - 8 === 0) {
      for (i = 0; i < data.length; i++) reg = t[(reg ^ data[i]) & 0xFF] & mask;
    } else {
      var sh = width - 8;
      for (i = 0; i < data.length; i++)
        reg = (((reg << 8) & mask) ^ t[(((reg >>> sh) & 0xFF) ^ data[i]) & 0xFF]) & mask;
    }
    if (refout !== refin) {
      var r = 0, v = reg;
      for (k = 0; k < width; k++) { r = (r << 1) | (v & 1); v >>>= 1; }
      reg = r & mask;
    }
    return (reg ^ xorout) & mask;
  }
  var IB = BigInt(init), XB = BigInt(xorout);
  var hi = Number(IB >> 32n) >>> 0, lo = Number(IB & 0xFFFFFFFFn) >>> 0;
  var TH = T.th, TL = T.tl;
  if (refin) {
    for (i = 0; i < data.length; i++) {
      var ix = (lo ^ data[i]) & 0xFF;
      var nl = ((lo >>> 8) | (hi << 24)) >>> 0, nh = (hi >>> 8) >>> 0;
      hi = (nh ^ TH[ix]) >>> 0; lo = (nl ^ TL[ix]) >>> 0;
    }
  } else {
    for (i = 0; i < data.length; i++) {
      var ix2 = ((hi >>> 24) ^ data[i]) & 0xFF;
      var carry = (lo >>> 24) & 0xFF;
      hi = ((((hi << 8) | carry) >>> 0) ^ TH[ix2]) >>> 0;
      lo = (((lo << 8) >>> 0) ^ TL[ix2]) >>> 0;
    }
  }
  /* ⚠ 反射分支与非反射分支的 refout 判据【相反】：反射域里寄存器已是反射序，
   * 只有 refout=false 才需转回正常序；非反射域则是 refout=true 才反转。
   * 统一写成 if (refout) 会正好在 crc64xz 上全错（长度仍正常、不报错）。 */
  if (refout !== refin) { var mh = bitrev32g(lo), ml = bitrev32g(hi); hi = mh; lo = ml; }
  var XH = Number(XB >> 32n) >>> 0, XL = Number(XB & 0xFFFFFFFFn) >>> 0;
  return [(hi ^ XH) >>> 0, (lo ^ XL) >>> 0];
}

function u64Hex(pair) {
  var s = pair[0].toString(16);
  while (s.length < 8) s = '0' + s;
  var t = pair[1].toString(16);
  while (t.length < 8) t = '0' + t;
  return s + t;
}
function fnv1a32(bytes) {
  var h = 0x811c9dc5;
  for (var i = 0; i < bytes.length; i++) {
    h ^= bytes[i];
    /* 乘以 FNV 素数 0x01000193，用 32 位拆分避免精度丢失 */
    h = (h + (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24)) >>> 0;
  }
  return h >>> 0;
}
function checksumNOut(v, nbytes, fmt) {
  var b = new Uint8Array(nbytes);
  if (nbytes === 1) b[0] = v & 0xFF;
  else if (nbytes === 2) { b[0] = (v >>> 8) & 0xFF; b[1] = v & 0xFF; }
  else if (nbytes === 4) { b[0] = (v >>> 24) & 0xFF; b[1] = (v >>> 16) & 0xFF; b[2] = (v >>> 8) & 0xFF; b[3] = v & 0xFF; }
  return bytesOut(b, fmt || 'hex');
}
function checksumOut(v, fmt) {
  var b = new Uint8Array(4);
  writeU32BE(v >>> 0, b, 0);
  return bytesOut(b, fmt || 'hex');
}
oneway({ id: 'crc32', name: 'CRC32', group: '校验和', key: false, param: false,
  info: 'CRC32（IEEE 802.3）：循环冗余校验，用于检测传输/存储中的意外改动。不是密码学算法，不能防篡改——需要防篡改请改用 HMAC 或 AEAD。',
  enc: function (b, k, p, fmt) { return checksumOut(crc32(b, false), fmt); } });
oneway({ id: 'crc32c', name: 'CRC32C (Castagnoli)', group: '校验和', key: false, param: false,
  info: 'CRC32C：Castagnoli 多项式，用于 iSCSI、SCTP、ext4 等。同样不是密码学算法。',
  enc: function (b, k, p, fmt) { return checksumOut(crc32c(b), fmt); } });
oneway({ id: 'adler32', name: 'Adler32', group: '校验和', key: false, param: false,
  info: 'Adler32：zlib 使用的滚动校验和，比 CRC32 快但对短数据较弱。同样不是密码学算法。',
  enc: function (b, k, p, fmt) { return checksumOut(adler32(b), fmt); } });

oneway({ id: 'crc8', name: 'CRC8（ATM / ITU）', group: '校验和', key: false, param: false,
  info: 'CRC8：8 位循环冗余校验，多项式 0x07，用于 SMBus、ATM 头校验等。数据量大时冲突率高，不能防篡改。',
  enc: function (b, k, p, fmt) { return checksumNOut(crcFast(b, 0x07, 0x00, false, false, 0x00, 8), 1, fmt); } });

oneway({ id: 'crc16ccitt', name: 'CRC16-CCITT（XMODEM）', group: '校验和', key: false, param: false,
  info: 'CRC16-CCITT：多项式 0x1021，初值 0x0000，用于 XMODEM、蓝牙、红外。出厂检查值 "123456789" → 31C3。',
  enc: function (b, k, p, fmt) { return checksumNOut(crcFast(b, 0x1021, 0x0000, false, false, 0x0000, 16), 2, fmt); } });

oneway({ id: 'crc16modbus', name: 'CRC16-MODBUS', group: '校验和', key: false, param: false,
  info: 'CRC16-MODBUS：多项式 0x8005，初值 FFFF，输入输出均反射，用于工业总线。检查值 "123456789" → 4B37。',
  enc: function (b, k, p, fmt) { return checksumNOut(crcFast(b, 0x8005, 0xFFFF, true, true, 0x0000, 16), 2, fmt); } });

oneway({ id: 'crc64ecma', name: 'CRC64-ECMA-182', group: '校验和', key: false, param: false,
  info: 'CRC64-ECMA-182：64 位 CRC，多项式 0x42F0E1EBA9EA3693，用于分布式存储去重。检查值 "123456789" → 6C40DF5F0B497347。',
  enc: function (b, k, p, fmt) { return u64Hex(crcFast(b, 0x42F0E1EBA9EA3693n, 0n, false, false, 0n, 64)); } });

oneway({ id: 'crc64xz', name: 'CRC64-XZ（Go ECMA）', group: '校验和', key: false, param: false,
  info: 'CRC64-XZ：与 ECMA 同多项式但初值/输出全 1 并反射，xz 压缩格式与 Go 标准库采用。',
  enc: function (b, k, p, fmt) { return u64Hex(crcFast(b, 0x42F0E1EBA9EA3693n, 0xFFFFFFFFFFFFFFFFn, true, true, 0xFFFFFFFFFFFFFFFFn, 64)); } });

oneway({ id: 'fnv1a32', name: 'FNV-1a 32', group: '校验和', key: false, param: false,
  info: 'FNV-1a 32：非密码学哈希，常用于哈希表与去重，比 CRC 快但冲突率更高。检查值 "foobar" → BF9CF968。',
  enc: function (b, k, p, fmt) { return checksumNOut(fnv1a32(b), 4, fmt); } });

/* ============================================================
 * FF1 格式保留加密（NIST SP 800-38G）
 *
 * 密文与明文【同长度、同字符集】：16 位卡号加密后仍是 16 位数字，
 * 适合无法改动字段类型的遗留系统、定长文件与既有校验逻辑。
 *
 * 注意：FF1 只提供机密性，不是哈希、也不是脱敏令牌；持有密钥即可还原。
 * ============================================================ */
function ff1AesEcbFn(keyBytes) {
  var a = null;
  for (var i = 0; i < ALGOS.length; i++) {
    var id = ALGOS[i].id;
    if ((keyBytes.length === 16 && id === 'aes128') ||
        (keyBytes.length === 24 && id === 'aes192') ||
        (keyBytes.length === 32 && id === 'aes256')) { a = ALGOS[i]; break; }
  }
  if (!a) throw new Error('FF1 只支持 128 / 192 / 256 位的 AES 密钥');
  var bf = a.makeBlockFn(keyBytes);
  return { enc: bf.enc, dec: bf.dec };
}
/* PRF(X)：以全零 IV 对 X 做 AES-CBC，取最后一个密文块（即 CBC-MAC） */
function ff1Prf(aesFn, X) {
  if (X.length === 0 || X.length % 16 !== 0) throw new Error('PRF 输入必须是 16 字节的整数倍');
  var c = new Uint8Array(16), blk = new Uint8Array(16);
  for (var i = 0; i < X.length; i += 16) {
    for (var j = 0; j < 16; j++) blk[j] = X[i + j] ^ c[j];
    c = aesFn.enc(blk);
  }
  return c;
}
function ff1NumRadix(digits, radix) {
  var x = 0n, r = BigInt(radix);
  for (var i = 0; i < digits.length; i++) x = x * r + BigInt(digits[i]);
  return x;
}
function ff1StrRadix(m, x, radix) {
  var r = BigInt(radix), out = new Array(m);
  var v = x;
  for (var i = m - 1; i >= 0; i--) { out[i] = Number(v % r); v = v / r; }
  return out;
}
function ff1B(num, b) {
  var out = new Uint8Array(b), v = num;
  for (var i = b - 1; i >= 0; i--) { out[i] = Number(v & 0xFFn); v >>= 8n; }
  return out;
}
function ff1Num(S) {
  var x = 0n;
  for (var i = 0; i < S.length; i++) x = (x << 8n) | BigInt(S[i]);
  return x;
}
function ff1Core(keyBytes, tweakBytes, digits, radix, encrypt) {
  var aesFn = ff1AesEcbFn(keyBytes);
  var n = digits.length, t = tweakBytes.length;
  var minLen = 2, maxLen = 1 << 16;
  if (n < minLen || n > maxLen) throw new Error('FF1 明文长度需在 2 ~ 65536 之间');
  if (radix < 2 || radix > 65536) throw new Error('FF1 的 radix 需在 2 ~ 65536 之间');
  var u = Math.floor(n / 2), v = n - u;
  var A = digits.slice(0, u), B = digits.slice(u);
  var b = Math.ceil(Math.ceil(v * Math.log2(radix)) / 8);
  var d = 4 * Math.ceil(b / 4) + 4;
  var P = new Uint8Array(16);
  P[0] = 1; P[1] = 2; P[2] = 1;
  P[3] = (radix >> 16) & 0xFF; P[4] = (radix >> 8) & 0xFF; P[5] = radix & 0xFF;
  P[6] = 10; P[7] = u & 0xFF;
  P[8] = (n >> 24) & 0xFF; P[9] = (n >> 16) & 0xFF; P[10] = (n >> 8) & 0xFF; P[11] = n & 0xFF;
  P[12] = (t >> 24) & 0xFF; P[13] = (t >> 16) & 0xFF; P[14] = (t >> 8) & 0xFF; P[15] = t & 0xFF;
  var padLen = ((-t - b - 1) % 16 + 16) % 16;
  var Qlen = t + padLen + 1 + b;
  var S = new Uint8Array(d);
  for (var i = 0; i < 10; i++) {
    var ii = encrypt ? i : (9 - i);
    var Q = new Uint8Array(Qlen);
    Q.set(tweakBytes, 0);
    Q[t + padLen] = ii;
    var numPart = encrypt ? B : A;
    var nb = ff1B(ff1NumRadix(numPart, radix), b);
    Q.set(nb, t + padLen + 1);
    var PQ = new Uint8Array(16 + Qlen);
    PQ.set(P, 0); PQ.set(Q, 16);
    var R = ff1Prf(aesFn, PQ);
    var Sfull = new Uint8Array(16 * Math.ceil(d / 16));
    Sfull.set(R, 0);
    for (var j = 1; j < Math.ceil(d / 16); j++) {
      var xb = new Uint8Array(16);
      for (var q = 0; q < 16; q++) xb[q] = R[q] ^ j;
      Sfull.set(aesFn.enc(xb), j * 16);
    }
    for (var q2 = 0; q2 < d; q2++) S[q2] = Sfull[q2];
    var y = ff1Num(S);
    var m = (ii % 2 === 0) ? u : v;
    var rBig = BigInt(radix);
    var mod = rBig ** BigInt(m);
    var c;
    if (encrypt) {
      c = (ff1NumRadix(A, radix) + y) % mod;
      var C = ff1StrRadix(m, c, radix);
      A = B; B = C;
    } else {
      c = (ff1NumRadix(B, radix) - y) % mod;
      if (c < 0n) c += mod;
      var C2 = ff1StrRadix(m, c, radix);
      B = A; A = C2;
    }
  }
  return A.concat(B);
}
/* 界面约定：密钥栏按 KDF 派生（16/24/32 字节）；参数栏填 radix（默认 10）；
   tweak 放在 IV/Nonce 栏（可选）。字母表用 0-9a-z。 */
var FF1_ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyz';
function ff1TextToDigits(text, radix) {
  var out = [];
  var s = String(text);
  for (var i = 0; i < s.length; i++) {
    var c = s[i].toLowerCase();
    var idx = FF1_ALPHABET.indexOf(c);
    if (idx < 0 || idx >= radix) throw new Error('字符「' + s[i] + '」不在当前 radix(' + radix + ') 的字符集内（可用 0-9 与小写 a-z）');
    out.push(idx);
  }
  return out;
}
function ff1DigitsToText(digits) {
  var s = '';
  for (var i = 0; i < digits.length; i++) s += FF1_ALPHABET[digits[i]];
  return s;
}
function ff1EncryptText(text, keyBytes, tweakBytes, radix) {
  return ff1DigitsToText(ff1Core(keyBytes, tweakBytes || new Uint8Array(0), ff1TextToDigits(text, radix), radix, true));
}
function ff1DecryptText(text, keyBytes, tweakBytes, radix) {
  return ff1DigitsToText(ff1Core(keyBytes, tweakBytes || new Uint8Array(0), ff1TextToDigits(text, radix), radix, false));
}

reg({ id:'ff1', name:'FF1 格式保留加密', group:'对称加密', key:true, param:true,
  keyLabel:'密钥（口令，走当前 KDF 派生 AES-256 密钥）',
  paramLabel:'radix（进制，默认 10；36 表示 0-9a-z）',
  param:true,
  info:'FF1（NIST SP 800-38G）：格式保留加密，密文与明文【同长度、同字符集】。' +
       '16 位卡号加密后仍是 16 位数字，适合无法改动字段类型的遗留系统。' +
       '已通过 NIST 官方样本验证（AES-128/192，radix 10 与 36，含带 tweak 的样本）。' +
       '注意：FF1 只提供机密性，不是哈希，持有密钥即可还原；tweak 建议由稳定的记录上下文（表名、租户 ID）派生。',
  enc: async function (b, k, p, f) {
    var radix = parseInt(p, 10); if (!radix || radix < 2 || radix > 36) radix = 10;
    var kb = (await deriveKeyFromPassword(k || '', 32, new Uint8Array(16))).key;
    var txt = bytesToStr(b).trim();
    if (txt.length < 2) throw new Error('FF1 明文至少需要 2 个字符');
    return ff1EncryptText(txt, kb, new Uint8Array(0), radix);
  },
  dec: async function (s, k, p, f) {
    var radix = parseInt(p, 10); if (!radix || radix < 2 || radix > 36) radix = 10;
    var kb = (await deriveKeyFromPassword(k || '', 32, new Uint8Array(16))).key;
    var txt = String(s).trim();
    if (txt.length < 2) throw new Error('FF1 密文至少需要 2 个字符');
    return ff1DecryptText(txt, kb, new Uint8Array(0), radix);
  } });

/* ---- ML-KEM（FIPS 203 后量子密钥封装）----
   与 kyber_py 双向互通验证：36 组自身往返 + 18 组跨实现互通 + 12 组隐式拒绝 + 尺寸校验。 */
function mlkemReg(id, name, k, info) {
  reg({ id: id, name: name, group: '后量子密码', key: true, param: false,
    keyLabel: '此算法需要密钥对，请先点【生成密钥】',
    info: info,
    isKem: true, kemK: k,
    gen: function () {
      var kp = mlkemKeygen(k);
      return { pub: bytesToHex(kp.ek), priv: bytesToHex(kp.dk) };
    },
    enc: function (b, kk, pp, fmt) {
      if (!kk) throw new Error('请先在参数栏填入对方的封装公钥（Hex），或先生成密钥对');
      var ek = hexToBytes(String(kk).replace(/\s/g, ''));
      var e = mlkemEncaps(k, ek);
      /* 输出「密文::K::共享密钥」。密文与共享密钥都用当前输出格式编码，
         否则解密端按同一格式解出的值与展示的 K 对不上。 */
      return bytesOut(e.c, fmt) + '\n::K::' + bytesOut(e.K, fmt);
    },
    dec: function (str, kk, pp, fmt) {
      if (!kk) throw new Error('请在密钥栏填入自己的解封装私钥（Hex）');
      var cHex = String(str).split('::K::')[0].trim();
      var c = bytesIn(cHex, fmt);
      return bytesOut(mlkemDecaps(k, hexToBytes(String(kk).replace(/\s/g, '')), c), fmt);
    } });
}
mlkemReg('mlkem512', 'ML-KEM-512（后量子 KEM）', 2,
  'ML-KEM-512：FIPS 203 标准化的后量子密钥封装机制（原 CRYSTALS-Kyber）。NIST 安全等级 1，大致对应 AES-128。公钥 800 字节、私钥 1632 字节、密文 768 字节，共享密钥 32 字节。');
mlkemReg('mlkem768', 'ML-KEM-768（后量子 KEM）', 3,
  'ML-KEM-768：FIPS 203，NIST 安全等级 3，大致对应 AES-192。这是推荐默认选项（也是 TLS 中最广泛部署的参数集）。公钥 1184 字节、私钥 2400 字节、密文 1088 字节。');
mlkemReg('mlkem1024', 'ML-KEM-1024（后量子 KEM）', 4,
  'ML-KEM-1024：FIPS 203，NIST 安全等级 5，大致对应 AES-256。公钥 1568 字节、私钥 3168 字节、密文 1568 字节。');

/* ---- ML-DSA（FIPS 204 后量子签名）----
   与 dilithium_py 双向互通验证：45 项自身往返/尺寸/篡改 + 12 项跨实现互通。 */
function mldsaReg(id, name, level, info) {
  reg({ id: id, name: name, group: '后量子密码', key: true, param: true,
    keyLabel: '签名填私钥 Hex，验签填公钥 Hex', paramLabel: '验签时填入签名',
    info: info,
    gen: function () { var kp = mldsaKeygen(level); return { pub: bytesToHex(kp.pk), priv: bytesToHex(kp.sk) }; },
    enc: function (b, kk, pp, fmt) {
      if (!kk) throw new Error('请先在密钥栏填入私钥（Hex），或先生成密钥对');
      var sk = hexToBytes(String(kk).replace(/\s/g, ''));
      return bytesOut(mldsaSign(level, sk, b, new Uint8Array(32)), fmt);
    },
    dec: function (str, kk, pp, fmt) {
      if (!kk) throw new Error('请在密钥栏填入公钥（Hex）');
      if (!pp) throw new Error('请在参数栏填入签名');
      var pk = hexToBytes(String(kk).replace(/\s/g, ''));
      var sig = bytesIn(String(pp).trim(), fmt);
      var msg = typeof str === 'string' ? strToBytes(str) : str;
      var ok = mldsaVerify(level, pk, msg, sig);
      return strToBytes(ok ? '验签通过：签名有效' : '验签失败：签名无效或数据被篡改');
    } });
}
mldsaReg('mldsa44', 'ML-DSA-44（后量子签名）', 44,
  'ML-DSA-44：FIPS 204 标准化的后量子数字签名（原 CRYSTALS-Dilithium）。NIST 安全等级 2。公钥 1312 字节、私钥 2560 字节、签名 2420 字节。');
mldsaReg('mldsa65', 'ML-DSA-65（后量子签名）', 65,
  'ML-DSA-65：FIPS 204，NIST 安全等级 3。推荐默认选项。公钥 1952 字节、私钥 4032 字节、签名 3309 字节。');
mldsaReg('mldsa87', 'ML-DSA-87（后量子签名）', 87,
  'ML-DSA-87：FIPS 204，NIST 安全等级 5。公钥 2592 字节、私钥 4896 字节、签名 4627 字节。');

/* ---- BLS12-381（IETF 标准配对曲线）----
   与 py_ecc（以太坊官方实现）交叉验证：45 项全过。 */
function blsParseHex(str, needBytes, what) {
  var h = String(str || '').replace(/\s/g, '');
  if (!/^[0-9a-fA-F]+$/.test(h)) throw new Error(what + ' 必须是 Hex 格式');
  if (h.length !== needBytes * 2) throw new Error(what + ' 应为 ' + needBytes + ' 字节（' + (needBytes * 2) + ' 个 Hex 字符），收到 ' + (h.length / 2));
  return hexToBytes(h);
}
reg({ id: 'bls_sig', name: 'BLS 签名（BLS12-381）', group: '椭圆曲线与高级代数', key: true, param: true,
  keyLabel: '签名填私钥 Hex，验签填公钥 Hex（G2，192 字节）', paramLabel: '验签时填入签名',
  info: 'BLS 签名（BLS12-381，G1 套件 BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_）：签名短（96 字节）、天然支持签名聚合。私钥 32 字节，公钥 192 字节（G2），签名 96 字节（G1）。这是以太坊信标链采用的曲线，但注意以太坊自身用的是 G2 签名套件。',
  gen: function () {
    var sk = crypto.getRandomValues(new Uint8Array(32));
    return { priv: bytesToHex(sk), pub: bytesToHex(blsG2ToBytes(blsSkToPk(blsBytesToSk(sk)))) };
  },
  enc: function (b, kk, pp, fmt) {
    if (!kk) throw new Error('请先在密钥栏填入私钥（32 字节 Hex），或先生成密钥对');
    var sk = blsBytesToSk(blsParseHex(kk, 32, '私钥'));
    return bytesOut(blsG1ToBytes(blsSign(sk, b)), fmt);
  },
  dec: function (str, kk, pp, fmt) {
    if (!kk) throw new Error('请在密钥栏填入公钥（G2，192 字节 Hex）');
    if (!pp) throw new Error('请在参数栏填入签名');
    var pk = blsG2FromBytes(blsParseHex(kk, 192, '公钥'));
    var sig = blsG1FromBytes(bytesIn(String(pp).trim(), fmt));
    var msg = typeof str === 'string' ? strToBytes(str) : str;
    return strToBytes(blsVerify(pk, msg, sig) ? '验签通过：签名有效' : '验签失败：签名无效或数据被篡改');
  } });
reg({ id: 'bls_pair', name: 'BLS12-381 配对 e(P,Q)', group: '椭圆曲线与高级代数', key: true, param: true,
  keyLabel: '密钥栏填 Q 点（G2，192 字节 Hex）', paramLabel: '参数栏填 P 点（G1，96 字节 Hex）',
  info: 'BLS12-381 的最优 Ate 配对 e(P, Q)，结果落在 FQ12（12 个系数，共 576 字节）。配对是 BLS 签名、身份加密、零知识证明的基础构件。与 py_ecc 逐系数比对通过。',
  enc: function (b, kk, pp, fmt) {
    if (!kk) throw new Error('请在密钥栏填入 Q 点（G2，192 字节 Hex）');
    if (!pp) throw new Error('请在参数栏填入 P 点（G1，96 字节 Hex）');
    var Q = blsG2FromBytes(blsParseHex(kk, 192, 'Q 点'));
    var P = blsG1FromBytes(blsParseHex(pp, 96, 'P 点'));
    var e = blsPairing(Q, P);
    var parts = [];
    for (var i = 0; i < 12; i++) parts.push(blsFqToBytes(e[i]));
    return bytesOut(blsCat(parts), fmt);
  },
  dec: function (str, kk, pp, fmt) {
    return strToBytes('配对是单向运算，没有对应的「解密」。如需验证双线性，可分别计算 e(aG1,bG2) 与 e(G1,G2)^(ab) 后比对。');
  } });

reg({ id: 'sphincs', name: 'SPHINCS+ 签名（SHAKE-128f）', group: '后量子密码', key: true, param: true,
  keyLabel: '签名填私钥（64 字节 Hex），验签填公钥（32 字节 Hex）', paramLabel: '验签时填入签名',
  info: 'SPHINCS+ 无状态哈希签名（SHAKE-256-128f，robust 变体，round-3）。安全性只依赖哈希函数，不依赖任何数学难题，因此抗量子。代价是签名很大：17088 字节（约 17 KB），密钥也较长（私钥 64 字节、公钥 32 字节）。签名较慢（需构建 22 层超树与 33 棵 FORS 树），请耐心等待。',
  gen: function () {
    var seed = crypto.getRandomValues(new Uint8Array(48));
    var kp = spxGenKeypair(seed);
    return { priv: bytesToHex(kp.sk), pub: bytesToHex(kp.pk) };
  },
  enc: function (b, kk, pp, fmt) {
    if (!kk) throw new Error('请先在密钥栏填入私钥（64 字节 Hex），或先生成密钥对');
    var h = String(kk).replace(/\s/g, '');
    if (!/^[0-9a-fA-F]+$/.test(h) || h.length !== 128)
      throw new Error('私钥应为 64 字节（128 个 Hex 字符），收到 ' + (h.length / 2) + ' 字节');
    return bytesOut(spxSign(b, hexToBytes(h), new Uint8Array(16)), fmt);
  },
  dec: function (str, kk, pp, fmt) {
    if (!kk) throw new Error('请在密钥栏填入公钥（32 字节 Hex）');
    if (!pp) throw new Error('请在参数栏填入签名');
    var h = String(kk).replace(/\s/g, '');
    if (!/^[0-9a-fA-F]+$/.test(h) || h.length !== 64)
      throw new Error('公钥应为 32 字节（64 个 Hex 字符），收到 ' + (h.length / 2) + ' 字节');
    var sig = bytesIn(String(pp).trim(), fmt);
    var msg = typeof str === 'string' ? strToBytes(str) : str;
    return strToBytes(spxVerify(msg, sig, hexToBytes(h))
      ? '验签通过：签名有效' : '验签失败：签名无效或数据被篡改');
  } });

/* ---- FROST 阈值签名（RFC 9591，Ed25519）---- */
reg({ id: 'frost', name: 'FROST 阈值签名 (Ed25519)', group: '非对称加密', key: true, param: true,
  keyLabel: '签名填份额包（JSON 或 "id:hex" 多行），验签填群公钥（32 字节 Hex）', paramLabel: '签名填参与者编号（如 1,3）；验签填签名（64 字节 Hex）',
  info: 'FROST（RFC 9591）两轮阈值签名：n 个参与者中任意 t 个合作才能签名，少于 t 个无法签名，全程不重建完整私钥，最终输出标准 Ed25519 签名。默认 t=2、n=3。份额用 nonce_generate 确定性派生（H3(随机数‖份额)），天然不存在随机数复用导致私钥泄露的风险。',
  gen: function () {
    var secret = scReduce(crypto.getRandomValues(new Uint8Array(32)));
    var d = frostTrustedDealer(secret, 2, 3);
    /* 必须转 Hex 字符串：Uint8Array 经 JSON.stringify 会变成 {0:..,1:..} 下标对象，
       还原时 hexToBytes 拿到的是对象，签名用的群公钥就成了错的。 */
    var obj = { t: 2, n: 3, groupPublicKey: bytesToHex(d.groupPublicKey), shares: {} };
    for (var k in d.shares) obj.shares[k] = bytesToHex(scLe(d.shares[k]));
    return { priv: JSON.stringify(obj), pub: bytesToHex(d.groupPublicKey) };
  },
  enc: function (b, kk, pp, fmt) {
    var obj;
    try { obj = JSON.parse(String(kk)); } catch (e) { obj = null; }
    if (!obj || !obj.shares) {
      /* 兼容 "id:hex" 多行写法 */
      obj = { shares: {} };
      var lines = String(kk).split(/[\n,;]+/);
      for (var i = 0; i < lines.length; i++) {
        var m = lines[i].trim().match(/^(\d+)\s*[:=]\s*([0-9a-fA-F]+)$/);
        if (m) obj.shares[m[1]] = m[2]; else throw new Error('份额格式无法解析：' + lines[i]);
      }
    }
    var ids = String(pp || '').split(/[\s,]+/).filter(function (x) { return x !== ''; }).map(Number);
    if (!ids.length) throw new Error('请在参数栏填入参与者编号，例如 1,3');
    var need = obj.t || Math.min(2, ids.length);
    if (ids.length < need) throw new Error('参与者数量 ' + ids.length + ' 少于阈值 ' + need);
    var shares = {};
    for (var j = 0; j < ids.length; j++) {
      var v = obj.shares[ids[j]];
      if (!v) throw new Error('缺少参与者 ' + ids[j] + ' 的份额');
      shares[ids[j]] = scReduce(hexToBytes(v));
    }
    var pk = obj.groupPublicKey ? hexToBytes(obj.groupPublicKey) : null;
    if (!pk) {
      var pts = [], xs = [];
      for (var q in shares) { xs.push(Number(q)); }
      var gp = [0n, 1n, 1n, 0n];
      for (var a = 0; a < xs.length; a++) {
        var lam = frostLagrange(xs[a], xs);
        gp = edProjAdd(gp, edProjMul(ED_B, (shares[xs[a]] * lam) % ED_L));
      }
      pk = edSerialize(edProjToAff(gp));
    }
    return bytesOut(frostSign(b, shares, ids, pk), fmt);
  },
  dec: function (str, kk, pp, fmt) {
    if (!kk) throw new Error('请在密钥栏填入群公钥（32 字节 Hex）');
    if (!pp) throw new Error('请在参数栏填入签名（64 字节 Hex）');
    var pk = hexToBytes(String(kk).replace(/\s/g, ''));
    var sig = bytesIn(String(pp).trim(), fmt);
    if (sig.length !== 64) throw new Error('签名应为 64 字节，收到 ' + sig.length);
    var msg = typeof str === 'string' ? strToBytes(str) : str;
    return strToBytes(frostVerify(sig, msg, pk) ? '验签通过：签名有效' : '验签失败：签名无效或数据被篡改');
  } });

reg({ id: 'gg20', name: 'GG20 阈值 ECDSA (secp256k1)', group: '非对称加密', key: true, param: true,
  keyLabel: '签名填份额包（JSON 或 "id:hex" 多行），验签填群公钥（65 字节 Hex，04 开头）', paramLabel: '签名填参与者编号（如 1,3）；验签填 "r,s"（十进制）',
  info: 'GG20（Gennaro & Goldfeder, ACM CCS 2020）阈值 ECDSA：t 个参与者合作产生标准 ECDSA 签名，全程不重建私钥。核心为 Paillier 同态加密 + MtA 乘法转加法。默认 t=2、n=3。⚠️ 本实现只含协议算术核心，未实现论文中的零知识证明，存在 Alpha-Rays（2023）类攻击面，仅用于学习与协议演示。',
  gen: function () {
    var curve = CURVES[GG20_CURVE], q = curve.n;
    var sk = 1n + (gg20RandBits(256) % (q - 1n));
    var sp = gg20ShamirSplit(sk, 2, 3, q);
    var obj = { t: 2, n: 3, groupPublicKey: bytesToHex(curve.pointToBytes(curve.mul(sk, { x: curve.gx, y: curve.gy }), false)), shares: {} };
    for (var i = 0; i < 3; i++) obj.shares[i + 1] = sp.shares[i].toString(16);
    return { priv: JSON.stringify(obj), pub: obj.groupPublicKey };
  },
  enc: function (b, kk, pp, fmt) {
    var obj;
    try { obj = JSON.parse(String(kk)); } catch (e) { obj = null; }
    if (!obj || !obj.shares) {
      obj = { shares: {} };
      var lines = String(kk).split(/[\n,;]+/);
      for (var i = 0; i < lines.length; i++) {
        var m = lines[i].trim().match(/^(\d+)\s*[:=]\s*([0-9a-fA-F]+)$/);
        if (m) obj.shares[m[1]] = m[2]; else throw new Error('份额格式无法解析：' + lines[i]);
      }
    }
    var ids = String(pp || '').split(/[\s,]+/).filter(function (x) { return x !== ''; }).map(Number);
    if (!ids.length) throw new Error('请在参数栏填入参与者编号，例如 1,3');
    var q = CURVES[GG20_CURVE].n, shares = [];
    for (var j = 0; j < ids.length; j++) {
      var v = obj.shares[ids[j]];
      if (!v) throw new Error('缺少参与者 ' + ids[j] + ' 的份额');
      shares.push(BigInt('0x' + v));
    }
    var d = sha256Bytes(b), mh = 0n;
    for (var z = 0; z < d.length; z++) mh = (mh << 8n) | BigInt(d[z]);
    var sig = gg20Sign(mh % q, shares, ids, obj.t || ids.length, obj.n || ids.length, 1024);
    return strToBytes(sig.r.toString(10) + ',' + sig.s.toString(10));
  },
  dec: function (str, kk, pp, fmt) {
    if (!kk) throw new Error('请在密钥栏填入群公钥（65 字节 Hex）');
    if (!pp) throw new Error('请在参数栏填入签名，格式 "r,s"（十进制）');
    var curve = CURVES[GG20_CURVE];
    var pt = curve.bytesToPoint(hexToBytes(String(kk).replace(/\s/g, '')));
    var m = String(pp).match(/\s*(\d+)\s*,\s*(\d+)\s*/);
    if (!m) throw new Error('签名格式应为 "r,s"（十进制整数）');
      var d = sha256Bytes(typeof str === 'string' ? strToBytes(str) : str), mh = 0n;
    for (var z = 0; z < d.length; z++) mh = (mh << 8n) | BigInt(d[z]);
    var ok = gg20Verify(mh % curve.n, { r: BigInt(m[1]), s: BigInt(m[2]) }, pt);
    return strToBytes(ok ? '验签通过：签名有效' : '验签失败：签名无效或数据被篡改');
  } });

/* ============================================================
 * AES-KWP（RFC 5649，带填充的密钥包装）
 * 与 AES-KW（RFC 3394）的区别：允许任意长度 ≥1 的明文，靠 4 字节 MLI 记长度。
 *
 * 关键实现点（都是踩过才确认的）：
 *  1. 单块判定是【填充后明文长度 == 8】，即明文 n ≤ 8，不是我最初写的
 *     「AIV+填充后 == 8 字节」。n ∈ {1,2,7,8} 才会走单块 ECB，
 *     写错时这四个长度全错、其余全对，极易漏检。
 *  2. AIV = A65959A6 ‖ MLI(n 的 32 位大端)，替代 KW 的 A6A6A6A6A6A6A6A6。
 *  3. 解包校验两条：AIV 前 4 字节必须匹配，且 MLI 之后的填充必须全 0。
 * ============================================================ */
var KWP_AIV = [0xA6, 0x59, 0x59, 0xA6];
function kwpMli(n) {
  return [Math.floor(n / 16777216) & 255, Math.floor(n / 65536) & 255, Math.floor(n / 256) & 255, n & 255];
}
function aesKwpWrap(keyBytes, plain) {
  var n = plain.length;
  if (n < 1 || n > 4294967295) throw new Error('AES-KWP 明文长度需在 1 ~ 2^32-1 之间（不能为空）');
  var padded = new Uint8Array(n + ((8 - n % 8) % 8));
  padded.set(plain, 0);
  var f = aesMakeBlockFn(keyBytes);
  var A = new Uint8Array(KWP_AIV.concat(kwpMli(n)));
  /* 填充后明文恰好 8 字节（n ≤ 8）：直接用单块 ECB，不走 KW 循环 */
  if (padded.length === 8) return f.enc(concatBytes(A, padded));
  var R = [];
  for (var i = 0; i < padded.length; i += 8) R.push(new Uint8Array(padded.subarray(i, i + 8)));
  var N = R.length;
  for (var j = 0; j < 6; j++) {
    for (var i = 0; i < N; i++) {
      var B = f.enc(concatBytes(A, R[i]));
      var t = N * j + i + 1;
      A = new Uint8Array(B.subarray(0, 8));
      /* 注意：>>> 的位数会被 &31，位移 ≥32 必须改用除法（与 aesKwWrap 同一坑） */
      for (var k = 0; k < 8; k++) {
        var sh = 8 * (7 - k);
        A[k] ^= (sh >= 32 ? Math.floor(t / Math.pow(2, sh)) : (t >>> sh)) & 255;
      }
      R[i] = new Uint8Array(B.subarray(8, 16));
    }
  }
  var out = new Uint8Array(8 * (N + 1));
  out.set(A, 0);
  for (var i = 0; i < N; i++) out.set(R[i], (i + 1) * 8);
  return out;
}
function aesKwpUnwrap(keyBytes, cipher) {
  if (cipher.length < 16 || cipher.length % 8) throw new Error('AES-KWP 密文需 ≥16 字节且为 8 的倍数');
  var f = aesMakeBlockFn(keyBytes);
  var P;
  /* 16 字节密文只可能来自单块路径（KW 路径输出恒 ≥24 字节） */
  if (cipher.length === 16) {
    P = f.dec(new Uint8Array(cipher));
  } else {
    var N = cipher.length / 8 - 1;
    var A = new Uint8Array(cipher.subarray(0, 8));
    var R = [];
    for (var i = 0; i < N; i++) R.push(new Uint8Array(cipher.subarray((i + 1) * 8, (i + 2) * 8)));
    for (var j = 5; j >= 0; j--) {
      for (var i = N - 1; i >= 0; i--) {
        var t = N * j + i + 1;
        var Ax = new Uint8Array(A);
        for (var k = 0; k < 8; k++) {
          var sh = 8 * (7 - k);
          Ax[k] ^= (sh >= 32 ? Math.floor(t / Math.pow(2, sh)) : (t >>> sh)) & 255;
        }
        var B = f.dec(concatBytes(Ax, R[i]));
        A = new Uint8Array(B.subarray(0, 8));
        R[i] = new Uint8Array(B.subarray(8, 16));
      }
    }
    var tmp = new Uint8Array(8 * (N + 1));
    tmp.set(A, 0);
    for (var i = 0; i < N; i++) tmp.set(R[i], (i + 1) * 8);
    P = tmp;
  }
  for (var i = 0; i < 4; i++) if (P[i] !== KWP_AIV[i]) throw new Error('AES-KWP 完整性校验失败：AIV 不匹配（密钥或密文不正确）');
  var mli = P[4] * 16777216 + P[5] * 65536 + P[6] * 256 + P[7];
  var padded = P.subarray(8);
  if (mli > padded.length) throw new Error('AES-KWP 长度字段非法：MLI 超出实际长度');
  for (var i = mli; i < padded.length; i++) if (padded[i] !== 0) throw new Error('AES-KWP 填充校验失败：填充字节非零');
  return new Uint8Array(padded.subarray(0, mli));
}

reg({ id: 'aes-kwp', name: 'AES-KWP（带填充密钥包装 RFC 5649）', group: '对称加密', key: true, param: false,
  keyLabel: 'KEK 包装密钥（任意字符串，派生 32 字节）',
  info: 'AES-KW 的带填充变体，可接受任意 ≥1 字节的明文（AES-KW 要求 ≥16 且为 8 的倍数）。内部用 4 字节 MLI 记录真实长度，解包时校验 AIV 与填充。输出比填充后明文多 8 字节。',
  enc: async function (b, k, p, fmt) {
    var kb = await deriveKeyBytes(k, 32);
    return bytesOut(aesKwpWrap(kb, b), fmt);
  },
  dec: async function (s, k, p, fmt) {
    var kb = await deriveKeyBytes(k, 32);
    return aesKwpUnwrap(kb, bytesIn(s, fmt));
  } });

/* AES-SIV（RFC 5297）独立条目：底层 aesSivEncrypt/Decrypt 早已存在，
   此前只作为「SIV 模式」的底层使用，没有独立入口。这里补上条目。 */
reg({ id: 'aes-siv', name: 'AES-SIV（RFC 5297 确定性 AEAD）', group: '对称加密', key: true, param: true,
  keyLabel: '密钥（任意字符串，派生 32 字节 = AES-128-SIV）',
  paramLabel: '关联数据 AD（可选，Hex 或文本）',
  info: '确定性认证加密：不需要 nonce，抗 nonce 误用（nonce 复用时不泄露明文异或）。输出 = V(16B)‖密文，密文与明文等长。密钥为 AES 密钥的两倍长。与 GCM-SIV（RFC 8452）不同，别混淆。',
  enc: async function (b, k, p, fmt) {
    var kb = await deriveKeyBytes(k, 32);
    var ad = String(p || '').trim() ? hexToBytes(String(p).trim()) : new Uint8Array(0);
    var r = aesSivEncrypt(b, kb, ad.length ? [ad] : []);
    return bytesOut(concatBytes(r.tag, r.ciphertext), fmt);
  },
  dec: async function (s, k, p, fmt) {
    var kb = await deriveKeyBytes(k, 32);
    var ad = String(p || '').trim() ? hexToBytes(String(p).trim()) : new Uint8Array(0);
    return aesSivDecrypt(bytesIn(s, fmt), kb, ad.length ? [ad] : []);
  } });
