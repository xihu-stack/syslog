"""风险行为记忆(2026-08-26): 每员工每场景的长期累积档案。全用sqlite3直连。"""
from __future__ import annotations
import sqlite3
import json
from collections import defaultdict
from datetime import datetime, timedelta

DB = "/app/data/ipguard.db"


def init_memory():
    db = sqlite3.connect(DB, timeout=60)
    db.execute("""CREATE TABLE IF NOT EXISTS risk_memory (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        employee_id TEXT NOT NULL, scenario TEXT NOT NULL,
        first_seen DATETIME, last_seen DATETIME,
        total_events INTEGER DEFAULT 0, total_alerts INTEGER DEFAULT 0,
        peak_score INTEGER DEFAULT 0, recent_score INTEGER DEFAULT 0,
        trend TEXT DEFAULT 'stable', evidence_summary TEXT,
        episode_count INTEGER DEFAULT 0, days_active INTEGER DEFAULT 0,
        updated_at DATETIME, UNIQUE(employee_id, scenario))""")
    db.commit()
    db.close()


def _trend(scores):
    if len(scores) < 4: return "insufficient"
    r = sum(scores[-5:]) / min(5, len(scores))
    e = sum(scores[:-5]) / max(1, len(scores[:-5]))
    if r > e + 8: return "rising"
    if r < e - 8: return "falling"
    return "stable"


def _episodes(dates):
    if not dates: return 0
    from datetime import datetime as _dt
    def _p(x):
        if isinstance(x, _dt): return x
        return _dt.fromisoformat(str(x)[:19])
    eps = 1
    for i in range(1, len(dates)):
        if (_p(dates[i]) - _p(dates[i-1])).days > 3: eps += 1
    return eps


def update_memory():
    """从verdicts/alerts重建记忆(小时级调用;verdict同窗口去重后 total_events=窗口数)。

    2026-08-26修复三处:
    - recent_score/trend 按时间序计算——旧版对scores单独sort后取[-1],recent恒等于
      peak、trend永不可能falling(全表17 rising/0 falling);
    - 规则直出场景(mass_exfil等verdict_id=None的告警)不再被丢弃,用告警自身
      窗口/分数撑起档案;
    - 未到期豁免的场景不进记忆——豁免只拦告警却照记档案并注入研判,是展佳
      "豁免后95分照进榜"的根因。
    """
    init_memory()
    from db import bj_now, write_lock as _wl
    s = sqlite3.connect(DB, timeout=120)
    s.row_factory = sqlite3.Row
    _ex = set()
    for r in s.execute("SELECT employee_id, signal_type FROM exceptions "
                       "WHERE expires_at IS NULL OR expires_at > datetime('now')").fetchall():
        _ex.add((r["employee_id"], r["signal_type"]))
    agg = defaultdict(lambda: {"pairs": [], "alert_count": 0, "evidence": [], "vc": 0})
    for v in s.execute("SELECT employee_id, intent, window_start, risk_score, explanation FROM verdicts WHERE risk_score>=30 AND intent!='normal_work'").fetchall():
        k = (v["employee_id"], v["intent"])
        agg[k]["pairs"].append((str(v["window_start"])[:19], v["risk_score"]))
        agg[k]["vc"] += 1
        exp = (v["explanation"] or "")[:200]
        if exp and exp not in [a[1] for a in agg[k]["evidence"][-3:]]:
            agg[k]["evidence"].append((str(v["window_start"])[:19], exp))
    for a in s.execute("SELECT employee_id, scenario, window_start, risk_score FROM alerts WHERE risk_score>=50").fetchall():
        k = (a["employee_id"], a["scenario"])
        agg[k]["alert_count"] += 1
        if not a["window_start"]:
            continue
        # 告警日期参与活跃期统计;分数只在无verdict的场景(规则直出)计入
        agg[k]["pairs"].append((str(a["window_start"])[:19],
                               a["risk_score"] if not agg[k]["pairs"] else None))
    s.close()

    rows = []
    for (emp, scen), d in agg.items():
        if not d["pairs"] or (emp, scen) in _ex:
            continue
        d["pairs"].sort(key=lambda x: x[0])   # 时间序: first/last/recent/trend都基于它
        dates = [p[0] for p in d["pairs"]]
        scores = [p[1] for p in d["pairs"] if p[1] is not None]
        days = len({dt[:10] for dt in dates})
        evt = " | ".join(f"{dt[5:10]}: {exp[:80]}" for dt, exp in d["evidence"][-3:])
        rows.append((emp, scen, dates[0], dates[-1], d["vc"], d["alert_count"],
                     max(scores), scores[-1], _trend(scores), evt, _episodes(dates), days, str(bj_now())[:19]))
    w = sqlite3.connect(DB, timeout=120)
    try:
        with _wl:  # 铁律: 全部写经write_lock串行(全表重写虽小也不例外)
            w.execute("BEGIN IMMEDIATE")
            w.execute("DELETE FROM risk_memory")
            w.executemany("INSERT OR REPLACE INTO risk_memory (employee_id,scenario,first_seen,last_seen,total_events,total_alerts,peak_score,recent_score,trend,evidence_summary,episode_count,days_active,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
            w.commit()
    finally:
        w.close()
    return len(rows)


def memory_for_llm(emp):
    """该员工的风险记忆摘要(喂给研判AI)。已豁免场景不注入(豁免=该场景不算风险)。"""
    try:
        db = sqlite3.connect(DB, timeout=30)
        db.row_factory = sqlite3.Row
        ex = {r["signal_type"] for r in db.execute(
            "SELECT signal_type FROM exceptions WHERE employee_id=? "
            "AND (expires_at IS NULL OR expires_at > datetime('now'))", (emp,)).fetchall()}
        rows = db.execute("SELECT * FROM risk_memory WHERE employee_id=? AND total_events>=2 ORDER BY last_seen DESC LIMIT 5", (emp,)).fetchall()
        db.close()
        rows = [r for r in rows if r["scenario"] not in ex]
        if not rows: return ""
        parts = []
        for r in rows:
            tc = {"rising": "↑上升", "falling": "↓下降", "stable": "→稳定"}.get(r["trend"], "")
            sc = {"data_exfiltration": "数据外发", "policy_violation": "违规", "job_seeking": "求职", "baseline_deviation": "行为偏离"}.get(r["scenario"], r["scenario"])
            parts.append(f"[{sc}] 首次{str(r['first_seen'])[:10]}~最近{str(r['last_seen'])[:10]},累计{r['total_events']}次/{r['total_alerts']}告警,峰值{r['peak_score']}/近期{r['recent_score']}{tc},活跃{r['days_active']}天/{r['episode_count']}个活跃期")
        return "\n【风险记忆】该员工历史行为档案(结合当前窗口综合判断,看风险轨迹而非孤立事件):\n" + "\n".join(parts)
    except Exception:
        return ""


def get_memory_api():
    try:
        db = sqlite3.connect(DB, timeout=30)
        db.row_factory = sqlite3.Row
        rows = db.execute("SELECT * FROM risk_memory ORDER BY peak_score DESC, last_seen DESC LIMIT 100").fetchall()
        db.close()
        return [dict(r) for r in rows]
    except Exception:
        return []
