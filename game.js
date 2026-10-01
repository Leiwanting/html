// game.js - 主游戏逻辑
// 依赖：break_eternity.js（Decimal）
// 依赖：save.js

// ===== 大数 =====
const D = (x) => new Decimal(x);

// ===== 全局变量（供 save.js 访问）=====
let game;
let SL_DATA, SPEED_UPGRADES, SF_UPGRADES;

window.addEventListener('DOMContentLoaded', () => {

  // ===== 游戏状态 =====
  game = {
    sp: D(10), sf: D(0), sl: [],
    speed: D(0.5), ringCap: D(100),
    multPerRing: D(0.1), asCount: 0,
    lastSaveTime: Date.now(),
  };

  // ===== SL 基础数据 =====
  SL_DATA = [
    { name:"The One",   color:"#f44", base:D(0.5),  cost:D(10),   growth:D(1.4) },
    { name:"The Two",   color:"#f84", base:D(5),    cost:D(100),  growth:D(1.5) },
    { name:"The Three", color:"#ff4", base:D(40),   cost:D(1e3),  growth:D(1.6) },
    { name:"The Four",  color:"#4f4", base:D(300),  cost:D(1e4),  growth:D(1.7) },
    { name:"The Five",  color:"#4ff", base:D(2e3),  cost:D(1e5),  growth:D(1.8) },
    { name:"The Six",   color:"#44f", base:D(1.5e4),cost:D(1e6),  growth:D(1.9) },
    { name:"The Seven", color:"#84f", base:D(1e5),  cost:D(1e7),  growth:D(2.0) },
    { name:"The Eight", color:"#f4f", base:D(8e5),  cost:D(1e8),  growth:D(2.1) },
    { name:"The Nine",  color:"#fff", base:D(6e6),  cost:D(1e9),  growth:D(2.2) },
    { name:"The Ten",   color:"#fd4", base:D(5e7),  cost:D(1e10), growth:D(2.4) },
  ];
  SL_DATA.forEach((d, i) => {
    game.sl.push({ level: D(0), rings: D(0), cost: d.cost });
  });

  // ===== 转速升级 =====
  SPEED_UPGRADES = [
    { id:"spd1", name:"转速 I",   cost:D(50),   costGrowth:D(1.8), max:10, bought:0, baseCost:D(50),   effect:()=>game.speed=game.speed.add(0.1) },
    { id:"spd2", name:"转速 II",  cost:D(1e3),  costGrowth:D(1.8), max:10, bought:0, baseCost:D(1e3),  effect:()=>game.speed=game.speed.add(0.2) },
    { id:"spd3", name:"转速 III", cost:D(1e5),  costGrowth:D(1.8), max:10, bought:0, baseCost:D(1e5),  effect:()=>game.speed=game.speed.add(0.5) },
    { id:"cap",  name:"圈数上限", cost:D(500),  costGrowth:D(2.0), max:10, bought:0, baseCost:D(500),  effect:()=>game.ringCap=game.ringCap.add(100) },
    { id:"mult", name:"叠乘系数", cost:D(5e3),  costGrowth:D(2.5), max:5,  bought:0, baseCost:D(5e3),  effect:()=>game.multPerRing=game.multPerRing.add(0.01) },
  ];

  // ===== SF 永久升级 =====
  SF_UPGRADES = [
    { id:"spdKeep", name:"转速继承", cost:D(5),  max:10, bought:0 },
    { id:"ringKeep", name:"圈数继承", cost:D(10), max:10, bought:0 },
    { id:"autoBuy",  name:"自动购买", cost:D(30), max:1,  bought:0 },
  ];

  window.SL_DATA = SL_DATA;
  window.SPEED_UPGRADES = SPEED_UPGRADES;
  window.SF_UPGRADES = SF_UPGRADES;
  window.getGame = () => game;
  window.setGame = (g) => { game = g; };

  // ===== 计算 =====
  function slProduction(i) {
    const d = SL_DATA[i], s = game.sl[i];
    if (s.level.lte(0)) return D(0);
    const mult = D(1).add(game.multPerRing).pow(s.rings);
    return d.base.mul(s.level).mul(mult);
  }
  function totalSPs() {
    let sum = D(0);
    for (let i = 0; i < game.sl.length; i++) sum = sum.add(slProduction(i));
    return sum;
  }
  window.getCurrentSPs = () => totalSPs();

  // ===== 购买 =====
  function buySL(i) {
    const s = game.sl[i];
    if (game.sp.lt(s.cost)) return;
    game.sp = game.sp.sub(s.cost);
    s.level = s.level.add(1);
    s.cost = s.cost.mul(SL_DATA[i].growth);
  }
  function buyAllSL() {
    for (let i = 0; i < game.sl.length; i++) {
      while (game.sp.gte(game.sl[i].cost)) buySL(i);
    }
  }
  function buySpeedUpgrade(u) {
    if (u.bought >= u.max) return;
    if (game.sp.lt(u.cost)) return;
    game.sp = game.sp.sub(u.cost);
    u.bought++;
    u.cost = u.cost.mul(u.costGrowth);
    u.effect();
  }
  function buySFUpgrade(u) {
    if (u.bought >= u.max) return;
    if (game.sf.lt(u.cost)) return;
    game.sf = game.sf.sub(u.cost);
    u.bought++;
  }

  // ===== AS =====
  function asGoal() { return D(1e4).mul(D(100).pow(game.asCount)); }
  function canAS() { return game.sp.gte(asGoal()); }
  function doAS() {
    if (!canAS()) return;
    const logSP = game.sp.log10();
    const sfGain = Decimal.floor(logSP.sub(4).pow(1.5).mul(10));
    game.sf = game.sf.add(sfGain);
    game.asCount++;
    game.sp = D(10);
    game.sl.forEach((s, i) => { s.level = D(0); s.rings = D(0); s.cost = SL_DATA[i].cost; });
    game.speed = D(0.5);
    game.ringCap = D(100);
    game.multPerRing = D(0.1);
    SPEED_UPGRADES.forEach(u => { u.bought = 0; u.cost = u.baseCost; });
  }

  // ===== 主循环 =====
  let lastTime = Date.now();
  function tick() {
    const now = Date.now();
    const dt = (now - lastTime) / 1000;
    lastTime = now;
    game.sp = game.sp.add(totalSPs().mul(dt));
    for (let i = 0; i < game.sl.length; i++) {
      const s = game.sl[i];
      if (s.level.lte(0)) continue;
      s.rings = s.rings.add(game.speed.mul(dt));
      if (s.rings.gt(game.ringCap)) s.rings = game.ringCap;
    }
    if (SF_UPGRADES[2].bought > 0) {
      for (let i = 0; i < game.sl.length; i++) {
        if (game.sp.gte(game.sl[i].cost)) buySL(i);
      }
    }
    render();
    requestAnimationFrame(tick);
  }

  // ===== 渲染 =====
  function fmt(d) {
    if (d.lt(1000)) return d.toFixed(2);
    if (d.lt(1e6)) return d.toFixed(2);
    return d.toExponential(2);
  }
  function render() {
    document.getElementById("sp").textContent = fmt(game.sp);
    document.getElementById("sps").textContent = fmt(totalSPs());
    document.getElementById("sf").textContent = fmt(game.sf);
    document.getElementById("as-count").textContent = game.asCount;
    document.getElementById("speed").textContent = fmt(game.speed);
    document.getElementById("ring-cap").textContent = fmt(game.ringCap);

    const slDiv = document.getElementById("sl-list");
    slDiv.innerHTML = "";
    SL_DATA.forEach((d, i) => {
      const s = game.sl[i];
      const div = document.createElement("div");
      div.className = "sl";
      div.innerHTML = `
        <span style="color:${d.color}">${d.name}</span>
        <span>Lv ${fmt(s.level)}</span>
        <span>圈 ${fmt(s.rings)}</span>
        <span>产 ${fmt(slProduction(i))}/s</span>
        <button ${game.sp.lt(s.cost)?"disabled":""}>买 (${fmt(s.cost)})</button>
      `;
      div.querySelector("button").onclick = () => buySL(i);
      slDiv.appendChild(div);
    });

    const spdDiv = document.getElementById("speed-upgrades");
    spdDiv.innerHTML = "";
    SPEED_UPGRADES.forEach(u => {
      const btn = document.createElement("button");
      btn.textContent = `${u.name} (${u.bought}/${u.max}) - ${fmt(u.cost)} SP`;
      btn.disabled = u.bought >= u.max || game.sp.lt(u.cost);
      btn.onclick = () => buySpeedUpgrade(u);
      spdDiv.appendChild(btn);
    });

    const asBtn = document.getElementById("as-btn");
    asBtn.disabled = !canAS();
    if (canAS()) {
      const sfGain = Decimal.floor(game.sp.log10().sub(4).pow(1.5).mul(10));
      asBtn.textContent = `AS! 获得 ${fmt(sfGain)} SF`;
    } else {
      asBtn.textContent = `需要 ${fmt(asGoal())} SP`;
    }
    asBtn.onclick = doAS;

    const sfDiv = document.getElementById("sf-upgrades");
    sfDiv.innerHTML = "";
    SF_UPGRADES.forEach(u => {
      const btn = document.createElement("button");
      btn.textContent = `${u.name} (${u.bought}/${u.max}) - ${fmt(u.cost)} SF`;
      btn.disabled = u.bought >= u.max || game.sf.lt(u.cost);
      btn.onclick = () => buySFUpgrade(u);
      sfDiv.appendChild(btn);
    });
  }

  // ===== 启动 =====
  document.getElementById("buy-all-sl").onclick = buyAllSL;

  document.getElementById("save-btn").onclick = () => {
    window.saveGame(window.getGame());
    alert("已保存");
  };
  document.getElementById("export-btn").onclick = () => {
    const str = window.exportSave(window.getGame());
    window.prompt("复制以下字符串，这是你目前存档的 JSON。\n\n" + str, str);
  };
  document.getElementById("import-btn").onclick = () => {
    const str = prompt("粘贴存档：");
    if (!str) return;
    const loaded = window.importSave(str);
    if (loaded) {
      window.setGame(loaded);
      alert("导入成功");
    } else {
      alert("导入失败，存档格式不对");
    }
  };
  document.getElementById("reset-btn").onclick = () => {
    if (!confirm("确定要重置存档吗？此操作不可撤销。")) return;
    window.resetSave();
    location.reload();
  };

  // 读档 + 离线收益
  if (typeof window.loadGame === "function") {
    const loaded = window.loadGame();
    if (loaded) {
      window.setGame(loaded);
      const gain = window.applyOfflineProgress(window.getGame());
      if (gain.gt(0)) {
        setTimeout(() => alert("离线收益: " + fmt(gain) + " SP"), 100);
      }
    }
  }

  // 自动保存（不改 lastSaveTime）
  setInterval(() => {
    if (typeof window.saveGame === "function") window.saveGame(window.getGame());
  }, 10000);

  // 页面隐藏 / 关闭时，记录时间并保存
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") {
      window.getGame().lastSaveTime = Date.now();
      window.saveGame(window.getGame());
    }
  });
  window.addEventListener("beforeunload", () => {
    window.getGame().lastSaveTime = Date.now();
    window.saveGame(window.getGame());
  });

  tick();
});