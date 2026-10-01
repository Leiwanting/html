// save.js - 存档模块
// 依赖：全局变量 SL_DATA、SPEED_UPGRADES、SF_UPGRADES
// 依赖：window.getGame() / window.setGame(g)

(function () {
  "use strict";

  const SAVE_KEY = "star_save_v1";
  const MAGIC = "Star_exportsave-";

  function serialize(g) {
    return JSON.stringify({
      sp: g.sp.toString(),
      sf: g.sf.toString(),
      speed: g.speed.toString(),
      ringCap: g.ringCap.toString(),
      multPerRing: g.multPerRing.toString(),
      asCount: g.asCount,
      lastSaveTime: g.lastSaveTime || Date.now(),
      sl: g.sl.map(s => ({
        level: s.level.toString(),
        rings: s.rings.toString(),
        cost: s.cost.toString(),
      })),
      speedUpgrades: SL_DATA && SPEED_UPGRADES ? SPEED_UPGRADES.map(u => ({
        bought: u.bought,
        cost: u.cost.toString(),
      })) : [],
      sfUpgrades: SF_UPGRADES ? SF_UPGRADES.map(u => ({
        bought: u.bought,
      })) : [],
    });
  }

  function deserialize(str) {
    try {
      const data = JSON.parse(str);
      const D = (x) => new Decimal(x);
      const g = {
        sp: D(data.sp), sf: D(data.sf), speed: D(data.speed),
        ringCap: D(data.ringCap), multPerRing: D(data.multPerRing),
        asCount: data.asCount || 0,
        lastSaveTime: data.lastSaveTime || Date.now(),
        sl: [],
      };
      SL_DATA.forEach((d, i) => {
        const saved = data.sl && data.sl[i];
        if (saved) {
          g.sl.push({ level: D(saved.level), rings: D(saved.rings), cost: D(saved.cost) });
        } else {
          g.sl.push({ level: D(0), rings: D(0), cost: d.cost });
        }
      });
      if (data.speedUpgrades) {
        SPEED_UPGRADES.forEach((u, i) => {
          const saved = data.speedUpgrades[i];
          if (saved) { u.bought = saved.bought; u.cost = D(saved.cost); }
          else { u.bought = 0; u.cost = u.baseCost; }
        });
      }
      if (data.sfUpgrades) {
        SF_UPGRADES.forEach((u, i) => {
          const saved = data.sfUpgrades[i];
          if (saved) u.bought = saved.bought;
        });
      }
      return g;
    } catch (e) {
      console.error("存档解析失败:", e);
      return null;
    }
  }

  window.saveGame = function (g) {
    try {
      localStorage.setItem(SAVE_KEY, serialize(g));
      return true;
    } catch (e) {
      console.error("保存失败:", e);
      return false;
    }
  };

  window.loadGame = function () {
    try {
      const str = localStorage.getItem(SAVE_KEY);
      if (!str) return null;
      return deserialize(str);
    } catch (e) {
      console.error("读取失败:", e);
      return null;
    }
  };

  window.exportSave = function (g) {
    return MAGIC + btoa(serialize(g));
  };

  window.importSave = function (str) {
    try {
      let clean = str.trim();
      if (clean.startsWith(MAGIC)) clean = clean.substring(MAGIC.length);
      return deserialize(atob(clean));
    } catch (e) {
      console.error("导入失败:", e);
      return null;
    }
  };

  window.resetSave = function () {
    localStorage.removeItem(SAVE_KEY);
  };

  // 离线收益
  window.applyOfflineProgress = function (g) {
    if (!g.lastSaveTime) return new Decimal(0);
    const now = Date.now();
    const elapsedSec = (now - g.lastSaveTime) / 1000;
    if (elapsedSec < 60) return new Decimal(0);

    const bestSPs = window.getCurrentSPs ? window.getCurrentSPs() : new Decimal(0);
    const offlineSP = bestSPs.mul(elapsedSec).mul(0.25);

    g.sp = g.sp.add(offlineSP);
    g.lastSaveTime = now;

    return offlineSP;
  };
})();