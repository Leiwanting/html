/* ============================================================
 * 算法选择器：八大分类折叠 + 顶部模糊搜索 + 搜索历史
 *
 * 设计要点：
 *  1. 原生 <select id="algo"> 保留但隐藏，作为"唯一状态源"。
 *     所有既有逻辑（读 value、派发 change）不受影响。
 *  2. 分类可折叠；只有「编码与古典密码」再细分出子分类。
 *  3. 搜索框位于面板最顶部，支持直接子串匹配与模糊（子序列）匹配。
 *  4. 历史搜索持久化到 localStorage，最多 8 条。
 * ============================================================ */

var ALGO_CATS = [
  {
    id: 'c-enc', name: '编码与古典密码', en: 'Encoding & Classical',
    subs: [
      { id: 'c-enc-1', name: '编码', en: 'Encoding',
        ids: ['base64', 'base32', 'base58', 'base85', 'url', 'html', 'unicode', 'hex', 'binary', 'octal'] },
      { id: 'c-enc-2', name: '古典密码', en: 'Classical',
        ids: ['rot13', 'caesar', 'morse', 'vigenere', 'atbash', 'affine', 'railfence', 'playfair', 'bacon'] },
      { id: 'c-enc-3', name: '其他', en: 'Other', ids: [] }
    ]
  },
  { id: 'c-hash',  name: '单向哈希与 KDF',     en: 'Hash & KDF',              byGroup: ['单向哈希'] },
  { id: 'c-sym',   name: '对称加密',           en: 'Symmetric',               byGroup: ['对称加密'] },
  { id: 'c-asym',  name: '非对称与密钥协商',   en: 'Asymmetric & Key Exchange',
    byGroup: ['非对称加密', '数字签名'] },
  { id: 'c-ec',    name: '椭圆曲线与高级代数', en: 'Elliptic Curves & Advanced Math',
    byGroup: ['椭圆曲线与高级代数'] },
  { id: 'c-pqc',   name: '后量子密码',         en: 'Post-Quantum (PQC)',      byGroup: ['后量子密码'] },
  { id: 'c-mpc',   name: '分布式与门限密码',   en: 'Distributed & Threshold (MPC)',
    byGroup: ['分布式与门限密码'] },
  { id: 'c-util',  name: '校验和与工具',       en: 'Checksums & Tools',
    byGroup: ['校验和', '密钥工具'] }
];

/* 按 id 的强制归类，优先级高于 byGroup。
 * 只放「按 group 会归错」的少数项：
 *   frost/gg20 的 group 是『非对称加密』，但它们属于门限密码；
 *   x25519 的 group 是『密钥工具』，但它本质是曲线算法。
 * ⚠ 历史上这里用 ids 白名单逐个列举，新增算法忘了加就静默掉进「其他」，
 *   一度有 23 个项目被误分。改成 group 驱动后不再有这个问题。 */
var ALGO_CAT_OVERRIDE = {
  'frost': { cat: 'c-mpc', sub: null },
  'gg20':  { cat: 'c-mpc', sub: null },
  'x25519': { cat: 'c-ec', sub: null }
};

var ALGO_CAT_FALLBACK = { cat: 'c-enc', sub: 'c-enc-3' };

var ALGO_PICK = {
  open: {},          /* 分类 id -> 是否展开 */
  subOpen: {},       /* 子分类 id -> 是否展开 */
  history: [],       /* 搜索历史 */
  recent: [],        /* 最近使用的算法 id */
  built: false
};

function algoCatOf(id, group) {
  if (ALGO_CAT_OVERRIDE[id]) return ALGO_CAT_OVERRIDE[id];
  for (var i = 0; i < ALGO_CATS.length; i++) {
    var c = ALGO_CATS[i];
    if (c.subs) {
      for (var j = 0; j < c.subs.length; j++) {
        if (c.subs[j].ids.indexOf(id) >= 0) return { cat: c.id, sub: c.subs[j].id };
      }
    }
    if (c.ids && c.ids.indexOf(id) >= 0) return { cat: c.id, sub: null };
    if (c.byGroup && c.byGroup.indexOf(group) >= 0) return { cat: c.id, sub: null };
  }
  return ALGO_CAT_FALLBACK;
}

/* mode='sub' 时只做连续子串匹配，不退化成子序列。
   子序列（x..c..b 按序出现即可）对短词毫无区分度：
   搜 "xcb" 会在 SPAKE2+ / CRC64 的说明文字里按序凑出 x、c、b，
   于是无关算法也进了结果。规定：
     · 查询长度 < 4   → 一律只子串（短词子序列必是噪声）
     · info 长文本    → 一律只子串（同上）
     · 分类名         → 一律只子串（名字本来就短，无需子序列）
   只有 name / id 在查询 ≥4 字符时才保留子序列模糊能力（如 "aes2"）。 */
var FUZZY_MINLEN = 4;
function fuzzyScore(query, text, mode) {
  if (!query) return 0;
  var q = query.toLowerCase(), t = String(text || '').toLowerCase();
  var idx = t.indexOf(q);
  if (idx >= 0) return 1000 - idx * 8 + (t.length === q.length ? 40 : 0);
  if (mode === 'sub' || q.length < FUZZY_MINLEN) return -1;
  var qi = 0, ti = 0, gaps = 0, last = -1;
  while (qi < q.length && ti < t.length) {
    if (q.charAt(qi) === t.charAt(ti)) {
      if (last >= 0 && ti - last > 1) gaps += (ti - last - 1);
      last = ti; qi++;
    }
    ti++;
  }
  if (qi === q.length) return Math.max(1, 420 - gaps * 6 - Math.floor(t.length / 4));
  return -1;
}

function algoMatchScore(q, a) {
  var w = algoCatOf(a.id, a.group);
  var cm = algoCatMeta(w.cat), sm = null;
  if (w.sub) {
    for (var i = 0; i < ALGO_CATS.length; i++) {
      if (ALGO_CATS[i].id !== w.cat || !ALGO_CATS[i].subs) continue;
      for (var j = 0; j < ALGO_CATS[i].subs.length; j++)
        if (ALGO_CATS[i].subs[j].id === w.sub) sm = ALGO_CATS[i].subs[j];
    }
  }
  var catScore = Math.max(
    cm ? fuzzyScore(q, cm.name, 'sub') : -1,
    cm ? fuzzyScore(q, cm.en, 'sub') : -1,
    sm ? fuzzyScore(q, sm.name, 'sub') : -1,
    sm ? fuzzyScore(q, sm.en, 'sub') : -1
  );
  if (catScore > 0) catScore = Math.min(catScore, 380);
  /* info 是长文本，只认连续子串，且封顶以免盖过真正的名字命中 */
  var infoScore = fuzzyScore(q, a.info || '', 'sub');
  if (infoScore > 0) infoScore = Math.min(infoScore, 300);
  var s = Math.max(
    fuzzyScore(q, a.name),
    fuzzyScore(q, a.id),
    infoScore,
    catScore
  );
  return s;
}

var HIST_KEY = 'algo_search_history_v1', RECENT_KEY = 'algo_recent_v1';
function loadHistory() {
  try {
    ALGO_PICK.history = JSON.parse(localStorage.getItem(HIST_KEY) || '[]');
    ALGO_PICK.recent = JSON.parse(localStorage.getItem(RECENT_KEY) || '[]');
  } catch (e) { ALGO_PICK.history = []; ALGO_PICK.recent = []; }
}
function pushHistory(q) {
  q = String(q || '').trim();
  if (!q) return;
  ALGO_PICK.history = [q].concat(ALGO_PICK.history.filter(function (x) { return x !== q; })).slice(0, 8);
  try { localStorage.setItem(HIST_KEY, JSON.stringify(ALGO_PICK.history)); } catch (e) {}
}
function clearHistory() {
  ALGO_PICK.history = [];
  try { localStorage.removeItem(HIST_KEY); } catch (e) {}
}
function pushRecent(id) {
  ALGO_PICK.recent = [id].concat(ALGO_PICK.recent.filter(function (x) { return x !== id; })).slice(0, 8);
  try { localStorage.setItem(RECENT_KEY, JSON.stringify(ALGO_PICK.recent)); } catch (e) {}
}

function algoEl(tag, cls, text) {
  var e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}
function algoCatMeta(cid) {
  for (var i = 0; i < ALGO_CATS.length; i++) if (ALGO_CATS[i].id === cid) return ALGO_CATS[i];
  return null;
}

function algoRenderPanel() {
  /* 渲染目标必须是内层 #algoList：若直接清空 #algoPanel，
     会把顶部的搜索框与历史记录一起删掉。 */
  var panel = document.getElementById('algoList');
  if (!panel) return;
  var q = (document.getElementById('algoSearch') || {}).value || '';
  q = q.trim();
  panel.innerHTML = '';

  if (q) {
    var hits = [];
    for (var i = 0; i < ALGOS.length; i++) {
      var sc = algoMatchScore(q, ALGOS[i]);
      if (sc > 0) hits.push({ a: ALGOS[i], s: sc });
    }
    hits.sort(function (x, y) { return y.s - x.s; });
    /* 相对阈值：只保留与最佳命中同量级的结果。
       否则"搜到一堆只沾边的"会淹没真正要找的那个。 */
    if (hits.length) {
      var top = hits[0].s, keep = [];
      for (var k = 0; k < hits.length; k++)
        if (hits[k].s >= top * 0.2 || hits[k].s >= 900) keep.push(hits[k]);
      hits = keep;
    }
    if (!hits.length) {
      panel.appendChild(algoEl('div', 'algo-empty', '没有匹配的算法，试试「AES」「SM2」「哈希」「门限」'));
      return;
    }
    var head = algoEl('div', 'algo-res-head', '匹配 ' + hits.length + ' 个算法');
    panel.appendChild(head);
    var shown = Math.min(hits.length, 60);
    for (var h = 0; h < shown; h++) {
      (function (item) {
        var where = algoCatOf(item.a.id, item.a.group);
        var cm = algoCatMeta(where.cat);
        var row = algoEl('div', 'algo-item algo-hit');
        var nm = algoEl('span', 'algo-hit-name', item.a.name);
        var ct = algoEl('span', 'algo-hit-cat', cm ? cm.name : '其他');
        row.appendChild(nm); row.appendChild(ct);
        row.addEventListener('click', function () { algoPickById(item.a.id); });
        panel.appendChild(row);
      })(hits[h]);
    }
    if (hits.length > shown) panel.appendChild(algoEl('div', 'algo-empty', '还有 ' + (hits.length - shown) + ' 个结果，请输入更具体的关键字'));
    return;
  }

  var bucket = {};
  for (var k = 0; k < ALGOS.length; k++) {
    var a = ALGOS[k], w = algoCatOf(a.id, a.group);
    var key = w.sub ? (w.cat + '|' + w.sub) : (w.cat + '|');
    if (!bucket[key]) bucket[key] = [];
    bucket[key].push(a);
  }

  for (var c = 0; c < ALGO_CATS.length; c++) {
    (function (cat) {
      var total = 0;
      for (var key in bucket) if (key.indexOf(cat.id + '|') === 0) total += bucket[key].length;
      if (!total) return;                       /* 空分类不显示 */
      var opened = !!ALGO_PICK.open[cat.id];

      var box = algoEl('div', 'algo-cat' + (opened ? ' is-open' : ''));
      var hd = algoEl('div', 'algo-cat-head');
      var arrow = algoEl('span', 'algo-arrow', opened ? '▾' : '▸');
      var nm = algoEl('span', 'algo-cat-name', cat.name);
      var en = algoEl('span', 'algo-cat-en', cat.en);
      var ct = algoEl('span', 'algo-cat-count', String(total));
      hd.appendChild(arrow); hd.appendChild(nm); hd.appendChild(en); hd.appendChild(ct);
      hd.addEventListener('click', function () {
        ALGO_PICK.open[cat.id] = !ALGO_PICK.open[cat.id];
        algoRenderPanel();
      });
      box.appendChild(hd);

      if (opened) {
        var body = algoEl('div', 'algo-cat-body');
        if (cat.subs) {
          for (var s = 0; s < cat.subs.length; s++) {
            (function (sub) {
              var list = bucket[cat.id + '|' + sub.id] || [];
              if (!list.length) return;          /* 空子分类不显示 */
              var sOpen = !!ALGO_PICK.subOpen[sub.id];
              var sb = algoEl('div', 'algo-sub' + (sOpen ? ' is-open' : ''));
              var sh = algoEl('div', 'algo-sub-head');
              sh.appendChild(algoEl('span', 'algo-arrow', sOpen ? '▾' : '▸'));
              sh.appendChild(algoEl('span', 'algo-sub-name', sub.name));
              sh.appendChild(algoEl('span', 'algo-sub-en', sub.en));
              sh.appendChild(algoEl('span', 'algo-cat-count', String(list.length)));
              sh.addEventListener('click', function () {
                ALGO_PICK.subOpen[sub.id] = !ALGO_PICK.subOpen[sub.id];
                algoRenderPanel();
              });
              sb.appendChild(sh);
              if (sOpen) {
                var lb = algoEl('div', 'algo-sub-body');
                for (var m = 0; m < list.length; m++) lb.appendChild(algoItemEl(list[m]));
                sb.appendChild(lb);
              }
              body.appendChild(sb);
            })(cat.subs[s]);
          }
        } else {
          var all = bucket[cat.id + '|'] || [];
          for (var m2 = 0; m2 < all.length; m2++) body.appendChild(algoItemEl(all[m2]));
        }
        box.appendChild(body);
      }
      panel.appendChild(box);
    })(ALGO_CATS[c]);
  }
}

function algoItemEl(a) {
  var row = algoEl('div', 'algo-item');
  var cur = (document.getElementById('algo') || {}).value;
  if (cur === a.id) row.className += ' is-active';
  row.appendChild(algoEl('span', 'algo-item-name', a.name));
  row.addEventListener('click', function () { algoPickById(a.id); });
  return row;
}

function algoPickById(id) {
  var sel = document.getElementById('algo');
  if (!sel) return;
  sel.value = id;
  if (sel.value !== id) {                     /* 极端情况：选项不存在 */
    for (var i = 0; i < ALGOS.length; i++) if (ALGOS[i].id === id) break;
    return;
  }
  pushRecent(id);
  algoClosePanel();
  algoSyncButton();
  try { sel.dispatchEvent(new Event('change')); } catch (e) {}
}

function algoSyncButton() {
  var sel = document.getElementById('algo');
  var btn = document.getElementById('algoBtn');
  var txt = document.getElementById('algoBtnText');
  if (!sel || !btn) return;
  var a = null;
  for (var i = 0; i < ALGOS.length; i++) if (ALGOS[i].id === sel.value) a = ALGOS[i];
  var label = a ? a.name : (sel.value || '请选择算法');
  if (txt) txt.textContent = label;
  var w = a ? algoCatOf(a.id, a.group) : null;
  var cm = w ? algoCatMeta(w.cat) : null;
  var sub = document.getElementById('algoBtnCat');
  if (sub) sub.textContent = cm ? cm.name : '';
}

function algoOpenPanel() {
  var p = document.getElementById('algoPanel');
  var b = document.getElementById('algoBtn');
  if (p) p.classList.remove('hidden');
  if (b) b.classList.add('is-open');
  var si = document.getElementById('algoSearch');
  if (si) setTimeout(function () { try { si.focus(); } catch (e) {} }, 30);
}
function algoClosePanel() {
  var p = document.getElementById('algoPanel');
  var b = document.getElementById('algoBtn');
  if (p) p.classList.add('hidden');
  if (b) b.classList.remove('is-open');
  var si = document.getElementById('algoSearch');
  if (si && (si.value || '').trim()) { pushHistory(si.value); algoRenderHistory(); }
}

function algoRenderHistory() {
  var box = document.getElementById('algoHist');
  if (!box) return;
  box.innerHTML = '';
  if (!ALGO_PICK.history.length) { box.classList.add('hidden'); return; }
  box.classList.remove('hidden');
  var lab = algoEl('span', 'algo-hist-label', '最近搜索');
  box.appendChild(lab);
  for (var i = 0; i < ALGO_PICK.history.length; i++) {
    (function (q) {
      var chip = algoEl('button', 'algo-hist-chip', q);
      chip.type = 'button';
      chip.addEventListener('click', function () {
        var si = document.getElementById('algoSearch');
        if (si) { si.value = q; algoRenderPanel(); }
      });
      box.appendChild(chip);
    })(ALGO_PICK.history[i]);
  }
  var clr = algoEl('button', 'algo-hist-clear', '清空');
  clr.type = 'button';
  clr.addEventListener('click', function () {
    clearHistory();
    var si = document.getElementById('algoSearch');
    if (si) si.value = '';
    algoRenderHistory(); algoRenderPanel();
  });
  box.appendChild(clr);
}

function initAlgoPicker() {
  var btn = document.getElementById('algoBtn');
  var panel = document.getElementById('algoPanel');
  var si = document.getElementById('algoSearch');
  var sel = document.getElementById('algo');
  if (!btn || !panel || !sel) return;

  /* 幂等：重复调用只重绘，不再挂第二套监听器。
     否则点击按钮时两个 handler 依次执行（开→关），面板永远打不开。 */
  if (ALGO_PICK.built) { algoRenderHistory(); algoRenderPanel(); algoSyncButton(); return; }

  loadHistory();
  var cur = sel.value;
  if (cur) {
    for (var i = 0; i < ALGOS.length; i++) {
      if (ALGOS[i].id === cur) {
        var w = algoCatOf(ALGOS[i].id, ALGOS[i].group);
        ALGO_PICK.open[w.cat] = true;
        if (w.sub) ALGO_PICK.subOpen[w.sub] = true;
        break;
      }
    }
  }

  btn.addEventListener('click', function (e) {
    e.stopPropagation();
    if (panel.classList.contains('hidden')) { algoRenderPanel(); algoOpenPanel(); }
    else algoClosePanel();
  });
  panel.addEventListener('click', function (e) { e.stopPropagation(); });
  document.addEventListener('click', function () { algoClosePanel(); });

  if (si) {
    si.addEventListener('input', function () { algoRenderPanel(); });
    si.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') { algoClosePanel(); return; }
      if (e.key === 'Enter') {
        var first = panel.querySelector('.algo-hit');
        if (first) { first.click(); return; }
        pushHistory(si.value);
        algoRenderHistory();
      }
    });
    si.addEventListener('blur', function () {
      if ((si.value || '').trim()) { pushHistory(si.value); algoRenderHistory(); }
    });
  }

  sel.addEventListener('change', algoSyncButton);
  algoRenderHistory();
  algoRenderPanel();
  algoSyncButton();
  ALGO_PICK.built = true;
}

if (typeof document !== 'undefined' && document.addEventListener) {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAlgoPicker);
  } else {
    initAlgoPicker();
  }
}
