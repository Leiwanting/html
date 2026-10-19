/* ============================================================
 * crypto_bip39.js —— BIP-39 助记词（生成 / 还原 / 种子派生）
 *
 * 依赖：crypto_bip39_words.js（2048 词官方词表，来自 bitcoin/bips）
 *      Encryption_and_decryption_logic.js（提供 reg / ALGOS / 工具）
 *
 * 规范：BIP-39 https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 *   熵 ENT ∈ {128,160,192,224,256} 位 → 校验 CS = ENT/32 位
 *   校验 = SHA-256(熵) 的前 CS 位
 *   (ENT+CS) 位按 11 位切分 → 词表索引 → 助记词
 *   种子 = PBKDF2-HMAC-SHA512(助记词, "mnemonic"+口令, 2048 轮, 64 字节)
 *
 * 向量：trezor/python-mnemonic 官方 vectors.json（english 共 24 组）
 * ============================================================ */
'use strict';
(function () {
  if (typeof ALGOS === 'undefined' || typeof reg !== 'function') {
    console.error('crypto_bip39.js 需要在 Encryption_and_decryption_logic.js 之后加载');
    return;
  }
  var W = globalThis.BIP39_WORDS;
  if (!W || W.length !== 2048) {
    console.error('crypto_bip39.js：BIP-39 词表缺失或非 2048 词');
    return;
  }
  var WIDX = {};
  for (var i = 0; i < W.length; i++) WIDX[W[i]] = i;

  /* ENT 位宽 ← 词数 */
  function entBitsByWords(n) {
    return ({ 12: 128, 15: 160, 18: 192, 21: 224, 24: 256 })[n] || 0;
  }
  function bytesToBin(b, bitLen) {
    var s = '';
    for (var i = 0; i < b.length; i++) s += b[i].toString(2).padStart(8, '0');
    return bitLen ? s.slice(0, bitLen) : s;
  }

  function utf8(s) { return new TextEncoder().encode(s); }
  function hx(b) {
    var s = '';
    for (var i = 0; i < b.length; i++) s += (b[i] < 16 ? '0' : '') + b[i].toString(16);
    return s;
  }
  function unhx(h) {
    h = String(h || '').replace(/[^0-9a-fA-F]/g, '');
    if (h.length % 2) throw new Error('Hex 长度须为偶数');
    var o = new Uint8Array(h.length / 2);
    for (var i = 0; i < o.length; i++) o[i] = parseInt(h.substr(i * 2, 2), 16);
    return o;
  }
  async function sha256(b) {
    var d = await crypto.subtle.digest('SHA-256', b);
    return new Uint8Array(d);
  }

  /* 熵 → 助记词 */
  async function entropyToMnemonic(entBytes) {
    var ENT = entBytes.length * 8;
    if ([128, 160, 192, 224, 256].indexOf(ENT) < 0) {
      throw new Error('熵长度须为 16/20/24/28/32 字节（128~256 位）');
    }
    var CS = ENT / 32;
    var chk = await sha256(entBytes);
    var bits = bytesToBin(entBytes) + bytesToBin(chk, CS);
    var words = [];
    for (var i = 0; i < bits.length; i += 11) {
      words.push(W[parseInt(bits.substr(i, 11), 2)]);
    }
    return words.join(' ');
  }

  /* 助记词 → 熵（含校验和验证，错误则抛错） */
  async function mnemonicToEntropy(mnemonic) {
    var words = String(mnemonic).trim().toLowerCase().split(/\s+/).filter(Boolean);
    var ENT = entBitsByWords(words.length);
    if (!ENT) throw new Error('助记词个数须为 12/15/18/21/24');
    var bits = '';
    for (var i = 0; i < words.length; i++) {
      var idx = WIDX[words[i]];
      if (idx === undefined) throw new Error('第 ' + (i + 1) + ' 个词「' + words[i] + '」不在 BIP-39 词表中');
      bits += idx.toString(2).padStart(11, '0');
    }
    var CS = ENT / 32;
    var entBits = bits.slice(0, ENT), chkBits = bits.slice(ENT, ENT + CS);
    if (bits.slice(ENT + CS).indexOf('1') >= 0) throw new Error('助记词尾部有多余位，可能已损坏');
    var ent = new Uint8Array(ENT / 8);
    for (var j = 0; j < ent.length; j++) ent[j] = parseInt(entBits.substr(j * 8, 8), 2);
    var want = bytesToBin(await sha256(ent), CS);
    if (want !== chkBits) throw new Error('✗ 校验和不匹配（助记词有误或被篡改）');
    return ent;
  }

  /* 助记词 + 口令 → 64 字节种子（BIP-32 根种子） */
  async function mnemonicToSeed(mnemonic, passphrase) {
    var salt = utf8('mnemonic' + (passphrase || ''));
    var key = await crypto.subtle.importKey('raw', utf8(mnemonic), 'PBKDF2', false, ['deriveBits']);
    var bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: salt, iterations: 2048, hash: 'SHA-512' }, key, 512);
    return new Uint8Array(bits);
  }

  /* ============================================================
   * 注册
   * ============================================================ */
  reg({
    id: 'bip39-mnemonic', name: 'BIP-39 助记词', group: '编码',
    key: false,
    param: false,
    info: 'BIP-39 助记词（比特币/以太坊钱包标准）。加密：输入熵 Hex（16/20/24/28/32 字节）→ 12~24 个助记词；解密：输入助记词 → 还原熵并校验校验和，篡改会报错。词表为 bitcoin/bips 官方 2048 词。',
    enc: async function (b) {
      /* 框架给 enc 的是已解码字节（勾选 Hex 输入时就是熵本身）；直接 String(b)
         会得到 "0,0,0,..." 这类逗号数字串，必须先判类型再用。 */
      var ent;
      if (b instanceof Uint8Array || ArrayBuffer.isView(b)) {
        ent = new Uint8Array(b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength));
        if (!ent.length) ent = null;
      } else {
        var s = String(b || '').trim();
        ent = s ? unhx(s) : null;
      }
      if (!ent) {
        ent = (function () {
          var r = new Uint8Array(16);
          if (typeof crypto !== 'undefined' && crypto.getRandomValues) crypto.getRandomValues(r);
          else for (var i = 0; i < 16; i++) r[i] = Math.floor(Math.random() * 256);
          return r;
        })();
      }
      return await entropyToMnemonic(ent);
    },
    dec: async function (input) {
      var ent = await mnemonicToEntropy(String(input || '').trim());
      return hx(ent) + '（校验和 ✓）';
    }
  });

  reg({
    id: 'bip39-seed', name: 'BIP-39 种子派生', group: '单向哈希',
    key: false,
    param: true, paramLabel: '口令 passphrase（可留空）',
    info: 'BIP-39 助记词 → BIP-32 根种子：PBKDF2-HMAC-SHA512(助记词, "mnemonic"+口令, 2048 轮, 64 字节)。输入助记词，参数栏填口令（官方向量用 "TREZOR"），输出 64 字节种子 Hex。',
    enc: async function (b, k, p) {
      /* 助记词是文本：框架传字节时按 UTF-8 还原，不能 String(bytes) */
      var m;
      if (b instanceof Uint8Array || ArrayBuffer.isView(b)) {
        var mb = new Uint8Array(b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength));
        m = (typeof globalThis.bytesToStr === 'function')
          ? globalThis.bytesToStr(mb)
          : (typeof TextDecoder !== 'undefined' ? new TextDecoder().decode(mb) : String.fromCharCode.apply(null, mb));
      } else {
        m = String(b || '');
      }
      m = m.trim();
      if (!m) throw new Error('请输入助记词');
      try { await mnemonicToEntropy(m); } catch (e) { throw new Error('助记词无效：' + e.message); }
      return hx(await mnemonicToSeed(m, String(p || '').trim()));
    },
    dec: false
  });

  if (typeof window.rebuildAlgoList === 'function') window.rebuildAlgoList();
})();
