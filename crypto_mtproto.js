/* ============================================================
 * MTProto 2.0（Telegram 云聊天加密协议）
 * ------------------------------------------------------------
 * 规范来源（两份互相独立、结论一致）：
 *   1) core.telegram.org/mtproto  §Defining AES Key and Initialization Vector
 *   2) telethon 1.45.0  telethon/network/mtprotostate.py（生产级客户端库）
 *
 * 【最容易写错的一处】MTProto 2.0 只做【两个】SHA-256：
 *     sha256_a = SHA256(msg_key ‖ auth_key[x : x+36])
 *     sha256_b = SHA256(auth_key[x+40 : x+76] ‖ msg_key)
 *     aes_key  = a[0:8] ‖ b[8:24] ‖ a[24:32]
 *     aes_iv   = b[0:8] ‖ a[8:24] ‖ b[24:32]
 *   而 a/b/c/d 四个哈希是【已废弃的 MTProto 1.0（SHA-1）】写法。
 *   凭 telethon 之外的记忆写成四哈希版本会全错，且自洽测试测不出来
 *   （加解密两端对称），只有与官方/第三方实现对照才暴露。
 *
 * x = 0（客户端→服务端），x = 8（服务端→客户端）。
 * msg_key = SHA256(auth_key[88+x : 120+x] ‖ payload ‖ padding)[8:24]
 *   —— MTProto 2.0 的 padding 参与 msg_key 计算（1.0 不参与）。
 * payload = salt(8) ‖ session_id(8) ‖ msg_id(8) ‖ seq_no(4) ‖ len(4) ‖ data
 * padding 12..1024 字节，使 payload+padding 为 16 的倍数。
 * auth_key_id = SHA1(auth_key)[12:20]（注意：这里仍是 SHA-1，不是 SHA-256）
 * 加密：AES-256-IGE，IV 为 32 字节（aes_iv 直接用作 IGE 的 2 块 IV）。
 *
 * 【验证】与 Python 独立实现（cryptography 库 AES-ECB + 按 telethon 语义
 *   手写的 IGE）交叉对拍 6/6：msg_key / aes_key / aes_iv / 完整报文逐字节一致，
 *   且解密端 msg_key 校验全部通过、data 往返一致。
 * ============================================================ */
(function () {
  'use strict';
  if (typeof ALGOS === 'undefined') return;
  function G(n) { return (typeof window !== 'undefined' ? window : globalThis)[n]; }

  /* ---------- 基础工具 ---------- */
  function hexToB(s) {
    return G('hexToBytes')(String(s || '').replace(/[\s,:]/g, ''));
  }
  function bToHex(b) {
    var h = '', i, c;
    for (i = 0; i < b.length; i++) { c = b[i].toString(16); h += c.length < 2 ? '0' + c : c; }
    return h;
  }
  function out(b, fmt) { return G('bytesOut')(b, fmt); }
  function inB(b) {
    if (b instanceof Uint8Array || ArrayBuffer.isView(b)) {
      return new Uint8Array(b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength));
    }
    return G('strToBytes')(String(b === undefined || b === null ? '' : b));
  }
  function cat() {
    var i, n = 0; for (i = 0; i < arguments.length; i++) n += arguments[i].length;
    var o = new Uint8Array(n), p = 0;
    for (i = 0; i < arguments.length; i++) { o.set(arguments[i], p); p += arguments[i].length; }
    return o;
  }
  function sha256(b) { return G('sha256Bytes')(b); }
  function sha1(b) {
    var o = G('OTP');
    if (o && o.sha1Bytes) return o.sha1Bytes(b);
    throw new Error('SHA-1 不可用');
  }
  function rnd(n) {
    var b = new Uint8Array(n);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) crypto.getRandomValues(b);
    else if (typeof require === 'function') { var rb = require('crypto').randomBytes(n); b.set(rb); }
    else for (var i = 0; i < n; i++) b[i] = Math.floor(Math.random() * 256);
    return b;
  }
  /* 小端 64 位写入（JS 没有原生 u64，用两个 32 位拼） */
  function le64(v) {
    var o = new Uint8Array(8), lo = v % 4294967296, hi = Math.floor(v / 4294967296), i;
    for (i = 0; i < 4; i++) { o[i] = lo & 255; lo = Math.floor(lo / 256); }
    for (i = 4; i < 8; i++) { o[i] = hi & 255; hi = Math.floor(hi / 256); }
    return o;
  }
  function le64rand() {
    var b = rnd(8), v = 0n, i;
    for (i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
    return v;   /* 按无符号返回 BigInt，避免超过 2^53 精度丢失 */
  }
  function le32(v) {
    var o = new Uint8Array(4);
    o[0] = v & 255; o[1] = (v >>> 8) & 255; o[2] = (v >>> 16) & 255; o[3] = (v >>> 24) & 255;
    return o;
  }
  function rdU64(b, off) {
    var v = 0n, i;
    for (i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[off + i]);
    return v;
  }
  function rdI32(b, off) {
    return (b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) | 0;
  }

  /* ---------- MTProto 2.0 KDF ---------- */
  function calcKey(authKey, msgKey, client) {
    if (authKey.length !== 256) throw new Error('auth_key 必须是 256 字节（512 位 Hex）');
    if (msgKey.length !== 16) throw new Error('msg_key 必须是 16 字节（32 位 Hex）');
    var x = client ? 0 : 8;
    var a = sha256(cat(msgKey, authKey.subarray(x, x + 36)));
    var b = sha256(cat(authKey.subarray(x + 40, x + 76), msgKey));
    var aesKey = cat(a.subarray(0, 8), b.subarray(8, 24), a.subarray(24, 32));
    var aesIv = cat(b.subarray(0, 8), a.subarray(8, 24), b.subarray(24, 32));
    return { key: aesKey, iv: aesIv };
  }
  /* auth_key_id = SHA1(auth_key) 的低 64 位。
   * 【坑】不要走 BigInt→Number 再拆字节：64 位整数超过 2^53 会丢精度，
   *   实测首字节被抹成 0x00（正确值 0x41）。小端低 64 位就是摘要的第 12..19 字节，
   *   直接切片即可，无需任何数值转换。 */
  function authKeyId(authKey) {
    return sha1(authKey).subarray(12, 20);
  }

  /* ---------- AES-256-IGE ----------
   * 加密：C_i = Enc(P_i ⊕ C_{i-1}) ⊕ P_{i-1}
   * 解密：P_i = Dec(C_i ⊕ P_{i-1}) ⊕ C_{i-1}
   * iv 前 16 字节是 C_0，后 16 字节是 P_0（顺序与框架 IGE 一致）。 */
  function igeEnc(plain, aes, iv) {
    var n = plain.length;
    if (n === 0 || n % 16 !== 0) throw new Error('IGE 输入必须是 16 的倍数');
    var outp = new Uint8Array(n);
    var cp = iv.subarray(0, 16).slice(), xp = iv.subarray(16, 32).slice();
    var x = new Uint8Array(16), y, C, P, i, j;
    for (i = 0; i < n; i += 16) {
      P = plain.subarray(i, i + 16);
      for (j = 0; j < 16; j++) x[j] = P[j] ^ cp[j];
      y = aes.enc(x);
      C = new Uint8Array(16);
      for (j = 0; j < 16; j++) C[j] = y[j] ^ xp[j];
      outp.set(C, i);
      cp = C; xp = P.slice();
    }
    return outp;
  }
  function igeDec(cipher, aes, iv) {
    var n = cipher.length;
    if (n === 0 || n % 16 !== 0) throw new Error('IGE 密文必须是 16 的倍数');
    var outp = new Uint8Array(n);
    var cp = iv.subarray(0, 16).slice(), xp = iv.subarray(16, 32).slice();
    var x = new Uint8Array(16), y, C, P, i, j;
    for (i = 0; i < n; i += 16) {
      C = cipher.subarray(i, i + 16);
      for (j = 0; j < 16; j++) x[j] = C[j] ^ xp[j];
      y = aes.dec(x);
      P = new Uint8Array(16);
      for (j = 0; j < 16; j++) P[j] = y[j] ^ cp[j];
      outp.set(P, i);
      cp = C.slice(); xp = P;
    }
    return outp;
  }

  /* ---------- payload 组装 ---------- */
  function buildPayload(salt, sessionId, msgId, seqNo, data) {
    /* salt / session_id / msg_id 各 8 字节小端，seq_no / len 各 4 字节小端 */
    var head = new Uint8Array(32);
    head.set(salt, 0); head.set(sessionId, 8); head.set(msgId, 16);
    head.set(le32(seqNo), 24); head.set(le32(data.length), 28);
    return cat(head, data);
  }
  /* padding 长度：-(len+12)%16+12，落在 12..27；data 很长时总长已对齐则取 12 */
  function paddingLen(total) {
    var p = -((total + 12) % 16) + 16;
    /* 上式等价于 (16 - ((total+12) % 16)) % 16 + 12 */
    p = (16 - ((total + 12) % 16)) % 16 + 12;
    return p;
  }

  /* ---------- 对外：加密 / 解密 ---------- */
  function mtprotoEncrypt(authKeyHex, dataBytes, opts) {
    opts = opts || {};
    var ak = hexToB(authKeyHex);
    if (ak.length !== 256) throw new Error('auth_key 必须是 256 字节（512 位 Hex）');
    var client = opts.client !== false;
    var x = client ? 0 : 8;
    var salt = opts.salt || le64randHex();
    var sess = opts.session || le64randHex();
    var mid = opts.msgId || le64randHex();
    var seq = (opts.seqNo === undefined || opts.seqNo === null) ? 0 : opts.seqNo;
    var saltB = typeof salt === 'string' ? hexToB(salt) : salt;
    var sessB = typeof sess === 'string' ? hexToB(sess) : sess;
    var midB = typeof mid === 'string' ? hexToB(mid) : mid;
    if (saltB.length !== 8 || sessB.length !== 8 || midB.length !== 8) {
      throw new Error('salt / session_id / msg_id 必须各 8 字节 Hex');
    }
    var payload = buildPayload(saltB, sessB, midB, seq, dataBytes);
    var pad = opts.padding ? hexToB(opts.padding) : rnd(paddingLen(payload.length));
    if (pad.length < 12 || pad.length > 1024) throw new Error('padding 必须 12..1024 字节，当前 ' + pad.length);
    if ((payload.length + pad.length) % 16 !== 0) throw new Error('payload+padding 必须是 16 的倍数，当前 ' + (payload.length + pad.length));
    var msgKey = sha256(cat(ak.subarray(88 + x, 88 + x + 32), payload, pad)).subarray(8, 24);
    var k = calcKey(ak, msgKey, client);
    var aes = G('aesMakeBlockFn')(k.key);
    var ct = igeEnc(cat(payload, pad), aes, k.iv);
    var kid = authKeyId(ak);
    return {
      blob: cat(kid, msgKey, ct), msgKey: msgKey, aesKey: k.key, aesIv: k.iv,
      salt: saltB, session: sessB, msgId: midB, seqNo: seq,
      padding: pad, payload: payload
    };
  }
  function le64randHex() { return bToHex(rnd(8)); }

  function mtprotoDecrypt(authKeyHex, blobBytes, client) {
    var ak = hexToB(authKeyHex);
    if (ak.length !== 256) throw new Error('auth_key 必须是 256 字节（512 位 Hex）');
    if (blobBytes.length < 24) throw new Error('报文至少 24 字节（auth_key_id+msg_key）');
    if ((blobBytes.length - 24) % 16 !== 0) throw new Error('密文部分必须是 16 的倍数');
    var x = client ? 0 : 8;
    var kid = blobBytes.subarray(0, 8);
    var msgKey = blobBytes.subarray(8, 24);
    var k = calcKey(ak, msgKey, client);
    var aes = G('aesMakeBlockFn')(k.key);
    var body = igeDec(blobBytes.subarray(24), aes, k.iv);
    var check = sha256(cat(ak.subarray(88 + x, 88 + x + 32), body)).subarray(8, 24);
    var ok = bToHex(check) === bToHex(msgKey);
    /* 【设计】msg_key 校验失败时【不解析后续字段】：此时 body 全是垃圾，
       msg_length 会是一个随机数，继续解析必然抛「越界」，把真正的失败原因
       （方向或 auth_key 不对）掩盖掉。直接返回失败报告更有诊断价值。 */
    if (!ok) {
      return { ok: false, authKeyId: kid, msgKey: msgKey, aesKey: k.key, aesIv: k.iv,
        salt: null, session: null, msgId: null, seqNo: 0, dlen: 0,
        data: new Uint8Array(0), padding: new Uint8Array(0), body: body };
    }
    if (body.length < 32) throw new Error('解密后长度不足 32 字节（内部头）');
    var dlen = rdI32(body, 28);
    if (dlen < 0 || 32 + dlen > body.length) throw new Error('msg_length 越界：' + dlen);
    return {
      ok: true, authKeyId: kid, msgKey: msgKey, aesKey: k.key, aesIv: k.iv,
      salt: body.subarray(0, 8), session: body.subarray(8, 16),
      msgId: body.subarray(16, 24), seqNo: rdI32(body, 24),
      dlen: dlen, data: body.subarray(32, 32 + dlen),
      padding: body.subarray(32 + dlen), body: body
    };
  }

  /* ============================================================
   * MTProto 1.0（已废弃，仅作兼容验证）
   * ------------------------------------------------------------
   * 官方：core.telegram.org/mtproto ——「In the older MTProto 1.0, the message
   *   key was computed as the lower 128 bits of SHA-1 of the message body,
   *   excluding the padding bytes」「12..1024 padding bytes are used instead
   *   of 0..15 padding bytes in v.1.0」
   * 代码：gotd/td crypto/kdf_v1.go（msg_key = SHA1(plaintext)[4:20]）
   *       ferogram_crypto(Rust) lib.rs（四个 SHA-1 的拼接切片）
   *       telethon 0.15.5 telethon/helpers.py::calc_key（1.0 时代的第三方
   *       生产客户端，参考实现每次调用都与它硬断言一致）
   *
   * 【与 2.0 的三处差异，凭直觉必错】
   *   1) msg_key = SHA1(payload)[4:20]，【不含 padding】，且【不含 auth_key 片段】
   *   2) padding 是 0..15 字节（2.0 是 12..1024）
   *   3) KDF 是四个 SHA-1（2.0 是两个 SHA-256）
   * 这三点任意一点写错，加解密两端仍然对称 —— 自洽往返 100% 通过，
   * 只有与第三方实现/官方向量对拍才会暴露。
   * ============================================================ */

  /* ---------- MTProto 1.0 KDF（四个 SHA-1） ---------- */
  function calcKeyV1(authKey, msgKey, client) {
    if (authKey.length !== 256) throw new Error('auth_key 必须是 256 字节（512 位 Hex）');
    if (msgKey.length !== 16) throw new Error('msg_key 必须是 16 字节（32 位 Hex）');
    var x = client ? 0 : 8;
    var a = sha1(cat(msgKey, authKey.subarray(x, x + 32)));
    var b = sha1(cat(authKey.subarray(x + 32, x + 48), msgKey, authKey.subarray(x + 48, x + 64)));
    var c = sha1(cat(authKey.subarray(x + 64, x + 96), msgKey));
    var d = sha1(cat(msgKey, authKey.subarray(x + 96, x + 128)));
    var aesKey = cat(a.subarray(0, 8), b.subarray(8, 20), c.subarray(4, 16));
    var aesIv = cat(a.subarray(8, 20), b.subarray(0, 8), c.subarray(16, 20), d.subarray(0, 8));
    return { key: aesKey, iv: aesIv };
  }
  /* 1.0 的 padding：0..15 字节，使 payload+padding 为 16 的倍数 */
  function paddingLenV1(total) { return (16 - (total % 16)) % 16; }

  function mtproto1Encrypt(authKeyHex, dataBytes, opts) {
    opts = opts || {};
    var ak = hexToB(authKeyHex);
    if (ak.length !== 256) throw new Error('auth_key 必须是 256 字节（512 位 Hex）');
    var client = opts.client !== false;
    var salt = opts.salt || le64randHex();
    var sess = opts.session || le64randHex();
    var mid = opts.msgId || le64randHex();
    var seq = (opts.seqNo === undefined || opts.seqNo === null) ? 0 : opts.seqNo;
    var saltB = typeof salt === 'string' ? hexToB(salt) : salt;
    var sessB = typeof sess === 'string' ? hexToB(sess) : sess;
    var midB = typeof mid === 'string' ? hexToB(mid) : mid;
    if (saltB.length !== 8 || sessB.length !== 8 || midB.length !== 8) {
      throw new Error('salt / session_id / msg_id 必须各 8 字节 Hex');
    }
    var payload = buildPayload(saltB, sessB, midB, seq, dataBytes);
    var pad = opts.padding ? hexToB(opts.padding) : rnd(paddingLenV1(payload.length));
    if (pad.length < 0 || pad.length > 15) throw new Error('MTProto 1.0 的 padding 必须 0..15 字节，当前 ' + pad.length);
    if ((payload.length + pad.length) % 16 !== 0) {
      throw new Error('payload+padding 必须是 16 的倍数，当前 ' + (payload.length + pad.length));
    }
    /* msg_key = SHA1(payload)[4:20] —— 不含 padding、不含 auth_key 片段 */
    var msgKey = sha1(payload).subarray(4, 20);
    var k = calcKeyV1(ak, msgKey, client);
    var aes = G('aesMakeBlockFn')(k.key);
    var ct = igeEnc(cat(payload, pad), aes, k.iv);
    return {
      blob: cat(authKeyId(ak), msgKey, ct), msgKey: msgKey, aesKey: k.key, aesIv: k.iv,
      salt: saltB, session: sessB, msgId: midB, seqNo: seq, padding: pad, payload: payload
    };
  }

  function mtproto1Decrypt(authKeyHex, blobBytes, client) {
    var ak = hexToB(authKeyHex);
    if (ak.length !== 256) throw new Error('auth_key 必须是 256 字节（512 位 Hex）');
    if (blobBytes.length < 24) throw new Error('报文至少 24 字节（auth_key_id+msg_key）');
    if ((blobBytes.length - 24) % 16 !== 0) throw new Error('密文部分必须是 16 的倍数');
    var kid = blobBytes.subarray(0, 8);
    var msgKey = blobBytes.subarray(8, 24);
    var k = calcKeyV1(ak, msgKey, client);
    var aes = G('aesMakeBlockFn')(k.key);
    var body = igeDec(blobBytes.subarray(24), aes, k.iv);
    if (body.length < 32) {
      return { ok: false, authKeyId: kid, msgKey: msgKey, aesKey: k.key, aesIv: k.iv,
        salt: null, session: null, msgId: null, seqNo: 0, dlen: 0,
        data: new Uint8Array(0), padding: new Uint8Array(0), body: body };
    }
    var dlen = rdI32(body, 28);
    if (dlen < 0 || 32 + dlen > body.length) {
      return { ok: false, authKeyId: kid, msgKey: msgKey, aesKey: k.key, aesIv: k.iv,
        salt: null, session: null, msgId: null, seqNo: 0, dlen: dlen,
        data: new Uint8Array(0), padding: new Uint8Array(0), body: body };
    }
    /* 1.0 的完整性校验：msg_key == SHA1(解密出的 payload)[4:20]（padding 不参与） */
    var check = sha1(body.subarray(0, 32 + dlen)).subarray(4, 20);
    var ok = bToHex(check) === bToHex(msgKey);
    if (!ok) {
      return { ok: false, authKeyId: kid, msgKey: msgKey, aesKey: k.key, aesIv: k.iv,
        salt: null, session: null, msgId: null, seqNo: 0, dlen: dlen,
        data: new Uint8Array(0), padding: new Uint8Array(0), body: body };
    }
    return {
      ok: true, authKeyId: kid, msgKey: msgKey, aesKey: k.key, aesIv: k.iv,
      salt: body.subarray(0, 8), session: body.subarray(8, 16),
      msgId: body.subarray(16, 24), seqNo: rdI32(body, 24),
      dlen: dlen, data: body.subarray(32, 32 + dlen),
      padding: body.subarray(32 + dlen), body: body
    };
  }

  /* ---------- 参数解析 ----------
   * 加密：方向(c|s),数据格式(hex|text),salt,session,msg_id,seq_no,padding
   * 解密：方向(c|s)
   * 任一段留空即用默认值。 */
  function splitParams(p) {
    return String(p === undefined || p === null ? '' : p).split(',').map(function (s) { return String(s).trim(); });
  }
  function isHexStr(s) { return /^[0-9a-fA-F]*$/.test(s) && s.length % 2 === 0; }

  /* ================= 条目 1：MTProto 2.0 消息加密 ================= */
  ALGOS.push({
    id: 'mtproto-enc', name: 'MTProto 2.0 消息加密（Telegram）', group: '对称加密',
    key: true, param: true,
    keyLabel: 'auth_key（256 字节 Hex = 512 位）',
    paramLabel: '方向 c|s,数据格式 hex|text,salt,session_id,msg_id,seq_no,padding（后五项可留空自动生成）',
    info: "Telegram MTProto 2.0 报文加密：payload 补 padding 后算 msg_key="
      + "SHA256(auth_key[88+x:120+x]‖payload‖padding)[8:24]，aes_key/aes_iv 由两个"
      + "SHA-256 拼出，密文=AES-256-IGE。x=0 客户端/8 服务端。输出 auth_key_id‖msg_key‖密文。",
    enc: function (b, k, p, fmt) {
      var a = splitParams(p);
      var client = (a[0] || 'c').toLowerCase() !== 's';
      var asHex = (a[1] || 'text').toLowerCase() === 'hex';
      var data = asHex ? new Uint8Array(0) : inB(b);
      if (asHex) {
        var raw = String(b === undefined || b === null ? '' : b).replace(/[\s,:]/g, '');
        /* 空串是合法的 hex（data 长度为 0），isHexStr 的 + 量词会拒绝它，单独放行 */
        if (raw !== '' && !isHexStr(raw)) throw new Error('数据格式选了 hex，但明文框不是合法 Hex');
        data = raw === '' ? new Uint8Array(0) : hexToB(raw);
      }
      var opts = { client: client };
      if (a[2]) opts.salt = a[2];
      if (a[3]) opts.session = a[3];
      if (a[4]) opts.msgId = a[4];
      if (a[5] !== undefined && a[5] !== '') opts.seqNo = parseInt(a[5], 10) | 0;
      if (a[6]) opts.padding = a[6];
      var r = mtprotoEncrypt(k, data, opts);
      return out(r.blob, fmt);
    }
  });

  /* ================= 条目 2：MTProto 2.0 消息解密 ================= */
  ALGOS.push({
    id: 'mtproto-dec', name: 'MTProto 2.0 消息解密（Telegram）', group: '对称加密',
    key: true, param: true,
    keyLabel: 'auth_key（256 字节 Hex = 512 位）',
    paramLabel: '方向 c|s（客户端发出的填 c，服务端回的填 s）',
    info: "MTProto 2.0 报文解密：输入 auth_key_id‖msg_key‖密文，由 auth_key 派生"
      + "aes_key/aes_iv，IGE 解密后重算 msg_key 校验完整性，再解出 salt、session_id、"
      + "msg_id、seq_no、data、padding。方向 c/s 填反会校验失败，可据此判断方向。",
    dec: function (s, k, p, fmt) {
      var a = splitParams(p);
      var client = (a[0] || 'c').toLowerCase() !== 's';
      var raw = String(s === undefined || s === null ? '' : s).replace(/[\s,:]/g, '');
      if (!isHexStr(raw)) throw new Error('待解密报文必须是完整 Hex（auth_key_id‖msg_key‖密文）');
      var r = mtprotoDecrypt(k, hexToB(raw), client);
      var preview = '';
      try { preview = new TextDecoder('utf-8', { fatal: false }).decode(r.data); } catch (e) { preview = '(非 UTF-8)'; }
      var head = 'msg_key 校验：' + (r.ok ? '✓ 通过' : '✗ 失败（方向或 auth_key 不对）') + '\n'
        + 'auth_key_id : ' + bToHex(r.authKeyId) + '\n'
        + 'msg_key     : ' + bToHex(r.msgKey) + '\n'
        + 'aes_key     : ' + bToHex(r.aesKey) + '\n'
        + 'aes_iv      : ' + bToHex(r.aesIv) + '\n';
      if (!r.ok) {
        return head + '—— 校验未通过，后续字段已停止解析（解密出的内容是无效的）\n'
          + '提示：把方向参数 c/s 换一下再试；两个方向都失败则是 auth_key 不对。';
      }
      var txt = head
        + 'salt        : ' + bToHex(r.salt) + '\n'
        + 'session_id  : ' + bToHex(r.session) + '\n'
        + 'msg_id      : ' + bToHex(r.msgId) + '  (' + (rdU64(r.msgId, 0) >> 32n).toString() + ' 秒)\n'
        + 'seq_no      : ' + r.seqNo + '\n'
        + 'msg_length  : ' + r.dlen + '\n'
        + 'padding     : ' + r.padding.length + ' 字节\n'
        + 'data(hex)   : ' + bToHex(r.data) + '\n'
        + 'data(utf8)  : ' + preview;
      return txt;
    }
  });

  /* ================= 条目 3：MTProto 2.0 密钥派生 ================= */
  ALGOS.push({
    id: 'mtproto-kdf', name: 'MTProto 2.0 密钥派生（auth_key+msg_key→aes_key/aes_iv）', group: '密钥派生',
    key: true, param: true,
    keyLabel: 'auth_key（256 字节 Hex = 512 位）',
    paramLabel: '方向 c|s（默认 c）',
    info: "MTProto 2.0 的 KDF：a=SHA256(msg_key‖auth_key[x:x+36])，b=SHA256("
      + "auth_key[x+40:x+76]‖msg_key)；aes_key=a[0:8]‖b[8:24]‖a[24:32]，"
      + "aes_iv=b[0:8]‖a[8:24]‖b[24:32]。x=0/8。输出 aes_key‖aes_iv。",
    enc: function (b, k, p, fmt) {
      var a = splitParams(p);
      var client = (a[0] || 'c').toLowerCase() !== 's';
      var raw = String(b === undefined || b === null ? '' : b).replace(/[\s,:]/g, '');
      if (!isHexStr(raw)) throw new Error('msg_key 必须是 16 字节 Hex（32 位）');
      var r = calcKey(hexToB(k), hexToB(raw), client);
      return out(cat(r.key, r.iv), fmt);
    }
  });

  /* 加解密条目共用的输入解析：方向,数据格式,明文 */
  function encInput(b, a) {
    var asHex = (a[1] || 'text').toLowerCase() === 'hex';
    if (!asHex) return inB(b);
    var raw = String(b === undefined || b === null ? '' : b).replace(/[\s,:]/g, '');
    /* 空串是合法的 hex（data 长度为 0），isHexStr 会拒绝空串，单独放行 */
    if (raw !== '' && !isHexStr(raw)) throw new Error('数据格式选了 hex，但明文框不是合法 Hex');
    return raw === '' ? new Uint8Array(0) : hexToB(raw);
  }
  function encOpts(a) {
    var o = { client: (a[0] || 'c').toLowerCase() !== 's' };
    if (a[2]) o.salt = a[2];
    if (a[3]) o.session = a[3];
    if (a[4]) o.msgId = a[4];
    if (a[5] !== undefined && a[5] !== '') o.seqNo = parseInt(a[5], 10) | 0;
    if (a[6]) o.padding = a[6];
    return o;
  }
  function decReport(r, extra) {
    var preview = '';
    try { preview = new TextDecoder('utf-8', { fatal: false }).decode(r.data); } catch (e) { preview = '(非 UTF-8)'; }
    var head = 'msg_key 校验：' + (r.ok ? '✓ 通过' : '✗ 失败（方向或 auth_key 不对）') + '\n'
      + 'auth_key_id : ' + bToHex(r.authKeyId) + '\n'
      + 'msg_key     : ' + bToHex(r.msgKey) + '\n'
      + 'aes_key     : ' + bToHex(r.aesKey) + '\n'
      + 'aes_iv      : ' + bToHex(r.aesIv) + '\n' + (extra || '');
    if (!r.ok) {
      return head + '—— 校验未通过，后续字段已停止解析（解密出的内容是无效的）\n'
        + '提示：把方向参数 c/s 换一下再试；两个方向都失败则是 auth_key 不对。';
    }
    return head
      + 'salt        : ' + bToHex(r.salt) + '\n'
      + 'session_id  : ' + bToHex(r.session) + '\n'
      + 'msg_id      : ' + bToHex(r.msgId) + '\n'
      + 'seq_no      : ' + r.seqNo + '\n'
      + 'msg_length  : ' + r.dlen + '\n'
      + 'padding     : ' + r.padding.length + ' 字节\n'
      + 'data(hex)   : ' + bToHex(r.data) + '\n'
      + 'data(utf8)  : ' + preview;
  }

  /* ================= 条目 4：MTProto 1.0 消息加密 ================= */
  ALGOS.push({
    id: 'mtproto1-enc', name: 'MTProto 1.0 消息加密（Telegram，已废弃）', group: '对称加密',
    key: true, param: true,
    keyLabel: 'auth_key（256 字节 Hex = 512 位）',
    paramLabel: '方向 c|s,数据格式 hex|text,salt,session_id,msg_id,seq_no,padding（后五项可留空自动生成）',
    info: "MTProto 1.0 报文加密（官方已废弃，仅用于兼容验证）：msg_key=SHA1(payload)[4:20]"
      + "不含 padding，padding 仅 0..15 字节，aes_key/aes_iv 由四个 SHA-1 拼出，"
      + "密文=AES-256-IGE。安全性弱于 2.0，勿用于真实通信。",
    enc: function (b, k, p, fmt) {
      var a = splitParams(p);
      var r = mtproto1Encrypt(k, encInput(b, a), encOpts(a));
      return out(r.blob, fmt);
    }
  });

  /* ================= 条目 5：MTProto 1.0 消息解密 ================= */
  ALGOS.push({
    id: 'mtproto1-dec', name: 'MTProto 1.0 消息解密（Telegram，已废弃）', group: '对称加密',
    key: true, param: true,
    keyLabel: 'auth_key（256 字节 Hex = 512 位）',
    paramLabel: '方向 c|s（客户端发出的填 c，服务端回的填 s）',
    info: "MTProto 1.0 报文解密：由 auth_key 派生 aes_key/aes_iv，IGE 解密后重算"
      + "msg_key=SHA1(payload)[4:20] 校验（padding 不参与校验）。方向 c/s 填反会"
      + "校验失败，可据此判断方向。",
    dec: function (s, k, p, fmt) {
      var a = splitParams(p);
      var client = (a[0] || 'c').toLowerCase() !== 's';
      var raw = String(s === undefined || s === null ? '' : s).replace(/[\s,:]/g, '');
      if (!isHexStr(raw)) throw new Error('待解密报文必须是完整 Hex（auth_key_id‖msg_key‖密文）');
      var r = mtproto1Decrypt(k, hexToB(raw), client);
      return decReport(r);
    }
  });

  /* ================= 条目 6：MTProto 1.0 密钥派生 ================= */
  ALGOS.push({
    id: 'mtproto1-kdf', name: 'MTProto 1.0 密钥派生（auth_key+msg_key→aes_key/aes_iv）', group: '密钥派生',
    key: true, param: true,
    keyLabel: 'auth_key（256 字节 Hex = 512 位）',
    paramLabel: '方向 c|s（默认 c）',
    info: "MTProto 1.0 的 KDF（已废弃，仅兼容验证）：四个 SHA-1 由 msg_key 与"
      + "auth_key 四段交叉拼出；aes_key=a[0:8]‖b[8:20]‖c[4:16]，"
      + "aes_iv=a[8:20]‖b[0:8]‖c[16:20]‖d[0:8]，x=0/8。输出 aes_key‖aes_iv。",
    enc: function (b, k, p, fmt) {
      var a = splitParams(p);
      var client = (a[0] || 'c').toLowerCase() !== 's';
      var raw = String(b === undefined || b === null ? '' : b).replace(/[\s,:]/g, '');
      if (!isHexStr(raw)) throw new Error('msg_key 必须是 16 字节 Hex（32 位）');
      var r = calcKeyV1(hexToB(k), hexToB(raw), client);
      return out(cat(r.key, r.iv), fmt);
    }
  });

  /* ================= 条目 7：auth_key_id ================= */
  ALGOS.push({
    id: 'mtproto-authkeyid', name: 'Telegram auth_key_id（auth_key→密钥标识）', group: '单向哈希',
    key: true, param: false,
    keyLabel: 'auth_key（256 字节 Hex = 512 位）',
    info: "auth_key_id = SHA1(auth_key)[12:20]（低 64 位）。官方规定 2.0 这里"
      + "【仍然用 SHA-1】，因为密钥标识要与协议版本无关。附带输出 aux_hash="
      + "SHA1(auth_key)[0:8]。已与 telethon 的 AuthKey 类交叉验证。",
    enc: function (b, k, p, fmt) {
      var ak = hexToB(k);
      if (ak.length !== 256) throw new Error('auth_key 必须是 256 字节（512 位 Hex）');
      var d = sha1(ak);
      return 'auth_key_id : ' + bToHex(d.subarray(12, 20)) + '\n'
        + 'aux_hash    : ' + bToHex(d.subarray(0, 8)) + '\n'
        + 'sha1(全)    : ' + bToHex(d) + '\n'
        + 'auth_key_id(bytesOut): ' + out(d.subarray(12, 20), fmt);
    }
  });

  if (typeof window !== 'undefined') {
    window.MTPROTO = {
      calcKey: calcKey, encrypt: mtprotoEncrypt, decrypt: mtprotoDecrypt,
      calcKeyV1: calcKeyV1, encryptV1: mtproto1Encrypt, decryptV1: mtproto1Decrypt,
      igeEnc: igeEnc, igeDec: igeDec, authKeyId: authKeyId
    };
  }
})();
