/* ============================================================
 * CRC-24 / OpenPGP（RFC 4880 的 CRC-24）
 * ------------------------------------------------------------
 * 参数（RFC 4880 §6.1，与 Botan 一致）：
 *   多项式 0x1864CFB（24 位，最高位隐含）
 *   初值   0xB704CE
 *   输入不反射、输出不反射、末尾不异或、不字节反转
 * 因此空输入的 CRC 直接等于初值 0xB704CE —— 这既是向量里第一条，
 * 也是判别「是否误加了 final xor」的最快探针。
 * 输出 3 字节大端。
 *
 * 向量：Botan 2.19.5 src/tests/data/hash/crc24.vec（[CRC24] 分节）
 * ============================================================ */
(function () {
  'use strict';
  if (typeof ALGOS === 'undefined') return;
  function G(n) { return (typeof window !== 'undefined' ? window : globalThis)[n]; }
  var push = (typeof reg === 'function') ? reg : function (o) { ALGOS.push(o); };

  var POLY = 0x1864CFB, INIT = 0xB704CE;

  function crc24(b) {
    var crc = INIT, i, j;
    for (i = 0; i < b.length; i++) {
      crc ^= b[i] << 16;                 /* 非反射：字节直接对齐到最高字节 */
      for (j = 0; j < 8; j++) {
        crc <<= 1;
        if (crc & 0x1000000) crc ^= POLY;
      }
    }
    return crc & 0xFFFFFF;
  }

  function toB(b) {
    if (b instanceof Uint8Array || ArrayBuffer.isView(b)) return new Uint8Array(b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength));
    return G('strToBytes')(String(b === undefined || b === null ? '' : b));
  }

  push({
    id: 'crc24', name: 'CRC-24（OpenPGP，RFC 4880）', group: '校验和',
    key: false, param: false,
    info: '24 位 CRC，OpenPGP（RFC 4880 §6.1）用它校验 ASCII Armor 的 Radix-64 数据，3 字节再编成 4 个 Base64 字符（前缀 "="）。多项式 0x1864CFB，初值 0xB704CE，非反射无末异或，故空输入即 0xB704CE。Botan 向量全通过。CRC 只能检错，不能当 MAC。',
    enc: function (b, k, p, fmt) {
      var c = crc24(toB(b));
      return G('bytesOut')(new Uint8Array([(c >> 16) & 255, (c >> 8) & 255, c & 255]), fmt);
    }
  });
})();
