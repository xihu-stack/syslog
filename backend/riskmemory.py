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
    eps = 1
    for i in range(1, len(dates)):
        if (dates[i] - dates[i-1]).days > 3: eps += 1
    return eps


def update_memory():
    """从verdicts/alerts重建记忆。"""
    init_memory()
    from db import bj_now
    s = sqlite3.connect(DB, timeout=120)
    s.row_factory = sqlite3.Row
    agg = defaultdict(lambda: {"dates": [], "scores": [], "alert_count": 0, "evidence": [], "vc": 0})
    for v in s.execute("SELECT employee_id, intent, window_start, risk_score, explanation FROM verdicts WHERE risk_score>=30 AND intent!='normal_work'").fetchall():
        k = (v["employee_id"], v["intent"])
        agg[k]["dates"].append(v["window_start"])
        agg[k]["scores"].append(v["risk_score"])
        agg[k]["vc"] += 1
        exp = (v["explanation"] or "")[:200]
        if exp and exp not in [a[1] for a in agg[k]["evidence"][-3:]]:
            agg[k]["evidence"].append((v["window_start"], exp))
    for a in s.execute("SELECT employee_id, scenario FROM alerts WHERE risk_score>=50").fetchall():
        k = (a["employee_id"], a["scenario"])
        agg[k]["alert_count"] += 1
    s.close()

    w = sqlite3.connect(DB, timeout=120)
    w.execute("DELETE FROM risk_memory")
    for (emp, scen), d in agg.items():
        d["dates"].sort(); d["scores"].sort()
        days = len({str(dt)[:10] for dt in d["dates"]})
        evt = " | ".join(f"{str(dt)[5:10]}: {exp[:80]}" for dt, exp in d["evidence"][-3:])
        w.execute("INSERT OR REPLACE INTO risk_memory (employee_id,scenario,first_seen,last_seen,total_events,total_alerts,peak_score,recent_score,trend,evidence_summary,episode_count,days_active,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (emp, scen, str(d["dates"][0])[:19], str(d["dates"][-1])[:19], d["vc"], d["alert_count"],
             max(d["scores"]), d["scores"][-1], _trend(d["scores"]), evt, _episodes(d["dates"]), days, str(bj_now())[:19]))
    w.commit()
    w.close()
    return len(agg)


def memory_for_llm(emp):
    """该员工的风险记忆摘要(喂给研判AI)。"""
    try:
        db = sqlite3.connect(DB, timeout=30)
        db.row_factory = sqlite3.Row
        rows = db.execute("SELECT * FROM risk_memory WHERE employee_id=? AND total_events>=2 ORDER BY last_seen DESC LIMIT 5", (emp,)).fetchall()
        db.close()
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
