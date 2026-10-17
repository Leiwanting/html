/* ============================================================
 * Merkle 树（RFC 6962 结构，Certificate Transparency 所用哈希树）
 *
 * 规则（RFC 6962 Section 2，与 Bitcoin/CT 一致）：
 *   叶子哈希  = SHA-256(0x00 || leafData)
 *   内部节点  = SHA-256(0x01 || left || right)
 *   奇数个节点时，最后一个节点「提升」到上一层（不复制）
 *
 * 两个前缀常量 0x00 / 0x01 是域分离关键：去掉它们会让「叶子数据」
 * 与「拼接后的内部节点」产生歧义，可被构造第二原像。
 *
 * 验证方式（无外部向量，靠结构自证）：
 *   1) 单叶子 root = SHA-256(0x00 || leaf)
 *   2) 双叶子 root = SHA-256(0x01 || LH || RH)
 *   3) 改变任一叶子，root 必变
 *   4) 包含证明沿路径重算必须回到同一个 root，且篡改后失败
 * ============================================================ */
(function () {
  if (typeof ALGOS === 'undefined' || typeof reg !== 'function') {
    console.error('crypto_merkle.js 需要在 Encryption_and_decryption_logic.js 之后加载');
    return;
  }

  function H(b) {
    if (typeof sha256BytesSync === 'function') return sha256BytesSync(b);
    if (typeof sha256Bytes === 'function') return sha256Bytes(b);
    throw new Error('找不到同步 SHA-256 实现');
  }
  function cat() {
    var n = 0, i;
    for (i = 0; i < arguments.length; i++) n += arguments[i].length;
    var o = new Uint8Array(n), p = 0;
    for (i = 0; i < arguments.length; i++) { o.set(arguments[i], p); p += arguments[i].length; }
    return o;
  }
  function b2h(b) {
    if (typeof bytesToHex === 'function') return bytesToHex(b);
    return Array.prototype.map.call(b, function (x) { return (x < 16 ? '0' : '') + x.toString(16); }).join('');
  }
  function h2b(h) {
    var c = String(h).replace(/[^0-9a-fA-F]/g, '');
    if (c.length % 2) c = '0' + c;
    var o = new Uint8Array(c.length / 2);
    for (var i = 0; i < o.length; i++) o[i] = parseInt(c.substr(i * 2, 2), 16);
    return o;
  }
  function toBytes(b) {
    if (typeof b === 'string') return typeof strToBytes === 'function' ? strToBytes(b) : (function () { var o = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) o[i] = b.charCodeAt(i) & 0xff; return o; })();
    return new Uint8Array(b);
  }
  function toStr(b) {
    if (typeof b === 'string') return b;
    if (b == null) return '';
    if (typeof bytesToStr === 'function') return bytesToStr(new Uint8Array(b));
    var s = ''; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return s;
  }

  var LEAF = new Uint8Array([0x00]);
  var NODE = new Uint8Array([0x01]);

  function leafHash(d) { return H(cat(LEAF, d)); }
  function nodeHash(l, r) { return H(cat(NODE, l, r)); }

  /* 自底向上建树，返回各层（level[0] = 叶子哈希层） */
  function build(leaves) {
    if (!leaves.length) throw new Error('至少需要 1 个叶子');
    var levels = [leaves.map(leafHash)];
    while (levels[levels.length - 1].length > 1) {
      var cur = levels[levels.length - 1], nxt = [], i;
      for (i = 0; i + 1 < cur.length; i += 2) nxt.push(nodeHash(cur[i], cur[i + 1]));
      /* 奇数个：最后一个提升（RFC 6962 规则） */
      if (cur.length % 2 === 1) nxt.push(cur[cur.length - 1]);
      levels.push(nxt);
    }
    return levels;
  }

  /* 生成第 idx 个叶子的包含证明：[(方向, 兄弟哈希), ...]，方向 0=兄弟在右，1=兄弟在左 */
  function prove(levels, idx) {
    var p = [];
    for (var lv = 0; lv < levels.length - 1; lv++) {
      var cur = levels[lv];
      if (idx % 2 === 0) {
        if (idx + 1 < cur.length) p.push({ side: 0, h: cur[idx + 1] });
      } else {
        p.push({ side: 1, h: cur[idx - 1] });
      }
      idx = Math.floor(idx / 2);
    }
    return p;
  }
  function verify(leafData, idx, proof, root) {
    var h = leafHash(leafData), i;
    for (i = 0; i < proof.length; i++) {
      h = proof[i].side === 0 ? nodeHash(h, proof[i].h) : nodeHash(proof[i].h, h);
    }
    if (h.length !== root.length) return false;
    for (i = 0; i < h.length; i++) if (h[i] !== root[i]) return false;
    return true;
  }

  /* 输入解析：每行一个叶子（先按 Hex 试，失败则按文本） */
  function parseLeaves(text) {
    var lines = String(text).split(/[\r\n]+/).map(function (s) { return s.trim(); }).filter(function (s) { return s.length; });
    if (!lines.length) throw new Error('请至少输入一行叶子数据');
    var allHex = lines.every(function (s) { return /^[0-9a-fA-F\s]+$/.test(s) && s.replace(/\s/g, '').length % 2 === 0; });
    return lines.map(function (s) {
      var t = s.replace(/\s/g, '');
      return allHex ? h2b(t) : toBytes(s);
    });
  }

  var ROOT_INFO = 'Merkle 树根（RFC 6962 结构，Certificate Transparency 所用）。输入区每行一个叶子（全为偶数位 Hex 时按字节解析，否则按文本）。叶子哈希 = SHA-256(0x00‖数据)，内部节点 = SHA-256(0x01‖左‖右)，奇数个时末位提升。输出 32 字节树根 Hex。';
  var PROOF_INFO = 'Merkle 包含证明（RFC 6962）。输入区每行一个叶子；参数栏填「叶子序号,声称的树根Hex」（序号从 0 起）。输出该叶子的证明路径、重算树根，以及是否与声称值一致。';

  reg({
    id: 'merkle-root', name: 'Merkle 树根（RFC 6962）', group: '单向哈希',
    key: false, param: false, dec: false,
    info: ROOT_INFO,
    enc: function (b) {
      var lv = parseLeaves(toStr(b));
      var levels = build(lv);
      var root = levels[levels.length - 1][0];
      var s = '树根: ' + b2h(root) + '\n叶子数: ' + lv.length;
      for (var i = 0; i < levels.length; i++) s += '\n第 ' + i + ' 层: ' + levels[i].length + ' 个节点';
      return s;
    }
  });

  reg({
    id: 'merkle-proof', name: 'Merkle 包含证明（RFC 6962）', group: '单向哈希',
    key: false, param: true, paramLabel: '叶子序号,声称的树根Hex（序号从 0 起；省略树根则只输出证明）',
    info: PROOF_INFO, dec: false,
    enc: function (b, k, p) {
      var lv = parseLeaves(toStr(b));
      var levels = build(lv);
      var root = levels[levels.length - 1][0];
      var parts = String(p || '').split(',');
      var idx = parseInt(String(parts[0] || '').trim(), 10);
      if (isNaN(idx)) idx = 0;
      if (idx < 0 || idx >= lv.length) throw new Error('叶子序号超出范围（0 .. ' + (lv.length - 1) + '）');
      var pr = prove(levels, idx);
      var s = '叶子 #' + idx + ' 的包含证明（' + pr.length + ' 步）:\n';
      for (var i = 0; i < pr.length; i++) s += '  ' + (i + 1) + '. ' + (pr[i].side === 0 ? '兄弟在右' : '兄弟在左') + ' ' + b2h(pr[i].h) + '\n';
      var okv = verify(lv[idx], idx, pr, root);
      s += '沿路径重算: ' + b2h(root) + (okv ? '（与树根一致 ✓）' : '（不一致 ✗）');
      var claim = String(parts[1] || '').trim();
      if (claim) {
        var cr = h2b(claim);
        if (cr.length !== 32) throw new Error('声称的树根须为 32 字节 Hex（64 个十六进制字符）');
        s += '\n声称树根: ' + b2h(cr) + (verify(lv[idx], idx, pr, cr) ? '  ✓ 证明有效' : '  ✗ 证明无效（叶子或树根不符）');
      }
      return s;
    }
  });

  globalThis.MERKLE = { leafHash: leafHash, nodeHash: nodeHash, build: build, prove: prove, verify: verify };
})();
