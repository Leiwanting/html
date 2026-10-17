/* ============================================================
 * TurboSHAKE128 / TurboSHAKE256 / KT128 / KT256 —— RFC 9861（IRTF CFRG）
 *
 * 为什么自成一族：它们用的是 Keccak-p[1600, n_r=12]，即**轮数减半**的置换。
 * 不是「少跑几轮的 SHA-3」——轮数从 24 降到 12 后，起始轮号是第 12 轮
 * （Keccak-p[n_r=12] 的定义），所以 keccakF(S, 12) 从 r=12 循环到 23。
 * 若误写成「跑 12 轮但从 r=0 开始」，输出长度完全正常、不报错、只静默全错。
 *
 * TurboSHAKE 的填充：input ‖ D ‖ 0* ‖ 0x80（末字节异或 0x80）。
 *   注意 D 是**域分隔字节**，直接替换 SHAKE 的 0x1F，不是追加在末尾的常量。
 *
 * KangarooTwelve = TurboSHAKE 上的 Sakura 树哈希：
 *   S = M ‖ C ‖ length_encode(|C|)
 *   length_encode(0) = 单字节 0x00（不是 right_encode 的 00 01）——这里极易写错。
 *   |S| ≤ 8192  →  单节点，域字节 0x07
 *   否则        →  中间节点 0x0B（每块 32/64 字节 CV），FinalNode 域字节 0x06
 *   FinalNode = S_0 ‖ 03 ‖ 00^7 ‖ CV_1..CV_(n-1) ‖ length_encode(n-1) ‖ FF FF
 *
 * 验证：RFC 9861 第 5 节官方向量 10/10（TurboSHAKE128×4、TurboSHAKE256×1、
 * KT128×4、KT256×1），另与 pycryptodome 交叉、与独立 Python 实现交叉。
 * ============================================================ */
(function () {

  function ptn(n) {
    var p = new Uint8Array(251);
    for (var i = 0; i < 251; i++) p[i] = i;
    var out = new Uint8Array(n);
    for (var j = 0; j < n; j++) out[j] = p[j % 251];
    return out;
  }

  /* RFC 9861 §3.3 length_encode(x)：大端最短表示 ‖ 长度字节。x=0 时只有 0x00。 */
  function lengthEncode(x) {
    var S = [];
    var v = x;
    while (v > 0) { S.unshift(v % 256); v = Math.floor(v / 256); }
    S.push(S.length);
    return new Uint8Array(S);
  }

  /* TurboSHAKE：12 轮 Keccak，域分隔字节 D 参与填充 */
  function turboShake(input, D, rateBytes, outLen) {
    var lanes = rateBytes / 8;
    var A = kecStateNew();
    var blocks = Math.floor(input.length / rateBytes);
    var i, b;
    for (b = 0; b < blocks; b++) {
      for (i = 0; i < lanes; i++) kecXorLane(A, i, input, b * rateBytes + i * 8);
      keccakF(A, 12);
    }
    var rem = input.length - blocks * rateBytes;
    var pad = new Uint8Array(rateBytes);
    for (i = 0; i < rem; i++) pad[i] = input[blocks * rateBytes + i];
    pad[rem] = D & 0xff;
    pad[rateBytes - 1] ^= 0x80;
    for (i = 0; i < lanes; i++) kecXorLane(A, i, pad, i * 8);
    keccakF(A, 12);

    var out = new Uint8Array(outLen);
    var pos = 0;
    while (pos < outLen) {
      var chunk = keccakStateToBytes(A, lanes);
      var take = Math.min(chunk.length, outLen - pos);
      out.set(chunk.subarray(0, take), pos);
      pos += take;
      if (pos < outLen) keccakF(A, 12);
    }
    return out;
  }

  /* KangarooTwelve / KT256：rate 168/136，CV 长度 32/64 */
  function kt(input, custom, outLen, rateBytes, cvLen) {
    var S = concatBytes(input, concatBytes(custom, lengthEncode(custom.length)));
    var B = 8192;
    var n = Math.ceil(S.length / B) || 1;
    if (n === 1) return turboShake(S, 0x07, rateBytes, outLen);
    var chunks = [];
    for (var i = 0; i < n; i++) chunks.push(S.subarray(i * B, Math.min((i + 1) * B, S.length)));
    var parts = [chunks[0], new Uint8Array([0x03, 0, 0, 0, 0, 0, 0, 0])];
    for (var j = 1; j < n; j++) parts.push(turboShake(chunks[j], 0x0B, rateBytes, cvLen));
    parts.push(lengthEncode(n - 1));
    parts.push(new Uint8Array([0xFF, 0xFF]));
    var finalNode = parts[0], k;
    for (k = 1; k < parts.length; k++) finalNode = concatBytes(finalNode, parts[k]);
    return turboShake(finalNode, 0x06, rateBytes, outLen);
  }

  /* ---- 参数解析：outLen 或 outLen:D 或 outLen:D:custom ---- */
  function splitParam(p) {
    var s = String(p == null ? '' : p).trim();
    return s ? s.split(':') : [];
  }
  function parseLen(v, def) {
    if (v === undefined || v === null || String(v).trim() === '') return def;
    var n = parseInt(String(v).trim(), 10);
    if (!isFinite(n) || n <= 0) throw new Error('输出长度必须是正整数');
    if (n > 4096) throw new Error('输出长度上限 4096 字节（当前 ' + n + '）');
    return n;
  }
  function parseD(v, def) {
    if (v === undefined || v === null || String(v).trim() === '') return def;
    var s = String(v).trim();
    var n = parseInt(s, 16);
    if (!isFinite(n) || n < 0 || n > 255) throw new Error('域分隔字节 D 须为 00-FF 的十六进制（当前 "' + s + '"）');
    return n;
  }
  var te = new TextEncoder();
  function parseCustom(v) {
    if (v === undefined || v === null || v === '') return new Uint8Array(0);
    var s = String(v);
    if (/^hex:/i.test(s)) {
      var h = s.slice(4).replace(/\s/g, '');
      if (!/^[0-9a-fA-F]*$/.test(h)) throw new Error('定制串 hex: 后须为十六进制');
      return hexToBytes(h);
    }
    return te.encode(s);
  }

  var G = '单向哈希';

  reg({
    id: 'turboshake128', name: 'TurboSHAKE128（12 轮 XOF）', group: G,
    key: false, param: true, paramLabel: '输出长度[:域分隔字节D(十六进制)]（默认 32:1F）',
    info: 'RFC 9861 的 TurboSHAKE128：Keccak 轮数减半（12 轮）的可扩展输出函数，比 SHAKE128 约快一倍，安全强度 128 位。参数填输出长度，可选填域分隔字节 D（默认 1F）。',
    enc: function (b, k, p, fmt) {
      var a = splitParam(p);
      return bytesOut(turboShake(b, parseD(a[1], 0x1F), 168, parseLen(a[0], 32)), fmt);
    }, dec: false
  });

  reg({
    id: 'turboshake256', name: 'TurboSHAKE256（12 轮 XOF）', group: G,
    key: false, param: true, paramLabel: '输出长度[:域分隔字节D(十六进制)]（默认 64:1F）',
    info: 'RFC 9861 的 TurboSHAKE256：12 轮 Keccak，安全强度 256 位，速率 136 字节。比 SHAKE256 约快一倍。参数填输出长度，可选填域分隔字节 D（默认 1F）。',
    enc: function (b, k, p, fmt) {
      var a = splitParam(p);
      return bytesOut(turboShake(b, parseD(a[1], 0x1F), 136, parseLen(a[0], 64)), fmt);
    }, dec: false
  });

  reg({
    id: 'kt128', name: 'KT128 / KangarooTwelve', group: G,
    key: false, param: true, paramLabel: '输出长度[:定制串]（定制串可用 hex: 前缀，默认 32 且无定制）',
    info: 'RFC 9861 的 KT128（即 KangarooTwelve）：在 TurboSHAKE128 上做树哈希，可并行、长输入远快于串行哈希。输入超过 8192 字节走树模式（中间节点 0B、终节点 06）。定制串用于域分隔。',
    enc: function (b, k, p, fmt) {
      var a = splitParam(p);
      var c = a.length > 1 ? a.slice(1).join(':') : '';
      return bytesOut(kt(b, parseCustom(c), parseLen(a[0], 32), 168, 32), fmt);
    }, dec: false
  });

  reg({
    id: 'kt256', name: 'KT256', group: G,
    key: false, param: true, paramLabel: '输出长度[:定制串]（定制串可用 hex: 前缀，默认 64 且无定制）',
    info: 'RFC 9861 的 KT256：KangarooTwelve 的 256 位强度版本，基于 TurboSHAKE256（速率 136，CV 长 64）。长输入走树哈希。定制串用于域分隔。',
    enc: function (b, k, p, fmt) {
      var a = splitParam(p);
      var c = a.length > 1 ? a.slice(1).join(':') : '';
      return bytesOut(kt(b, parseCustom(c), parseLen(a[0], 64), 136, 64), fmt);
    }, dec: false
  });

  globalThis.TS = { turboShake: turboShake, kt: kt, ptn: ptn, lengthEncode: lengthEncode };
})();
