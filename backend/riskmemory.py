"""风险行为记忆(2026-08-26): 每员工每场景的长期累积档案。
核心思想(用户口径): "每个人的行为都应该有记忆,尤其是风险行为,可以给到最新的日志结合一期看"——
不是孤立地看单次事件,而是看到完整的风险演进轨迹(首次/最近/频次/趋势/证据链)。
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timedelta

from db import (Session, EventRow, VerdictRow, AlertRow, ProfileRow,
                Base, engine, bj_now, write_lock, severity_of)
import dicts


def init_memory():
    """建表(幂等)。"""
    with engine.connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS risk_memory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_id TEXT NOT NULL,
                scenario TEXT NOT NULL,
                first_seen DATETIME,
                last_seen DATETIME,
                total_events INTEGER DEFAULT 0,
                total_alerts INTEGER DEFAULT 0,
                peak_score INTEGER DEFAULT 0,
                recent_score INTEGER DEFAULT 0,
                trend TEXT DEFAULT 'stable',
                evidence_summary TEXT,
                episode_count INTEGER DEFAULT 0,
                days_active INTEGER DEFAULT 0,
                updated_at DATETIME,
                UNIQUE(employee_id, scenario)
            )
        """)
        conn.commit()


def _trend(scores: list[int]) -> str:
    """趋势判定: 最近5次 vs 之前5次。"""
    if len(scores) < 4:
        return "insufficient"
    recent = sum(scores[-5:]) / min(5, len(scores))
    earlier = sum(scores[:-5]) / max(1, len(scores[:-5]))
    if recent > earlier + 8:
        return "rising"
    if recent < earlier - 8:
        return "falling"
    return "stable"


def _episodes(dates: list[datetime]) -> int:
    """活跃期数: 间隔>3天算新episode。"""
    if not dates:
        return 0
    eps = 1
    for i in range(1, len(dates)):
        if (dates[i] - dates[i-1]).days > 3:
            eps += 1
    return eps


def update_memory():
    """从verdicts/alerts重建全量记忆(每小时维护调用)。"""
    init_memory()
    s = Session()
    try:
        # 按员工×场景聚合
        agg = defaultdict(lambda: {
            "dates": [], "scores": [], "alert_count": 0,
            "evidence": [], "verdict_count": 0
        })
        for v in s.query(VerdictRow).filter(
                VerdictRow.risk_score >= 30,
                VerdictRow.intent != "normal_work").all():
            k = (v.employee_id, v.intent)
            agg[k]["dates"].append(v.window_start)
            agg[k]["scores"].append(v.risk_score)
            agg[k]["verdict_count"] += 1
            # 取explanation里的关键证据(文件名/域名)
            exp = (v.explanation or "")[:200]
            if exp and exp not in [a[1] for a in agg[k]["evidence"][-3:]]:
                agg[k]["evidence"].append((v.window_start, exp))

        for a in s.query(AlertRow).filter(AlertRow.risk_score >= 50).all():
            k = (a.employee_id, a.scenario)
            agg[k]["alert_count"] += 1

        with write_lock:
            ws = Session()
            try:
                ws.execute("DELETE FROM risk_memory")
                for (emp, scen), d in agg.items():
                    d["dates"].sort()
                    d["scores"].sort()
                    days = len({dt.date() for dt in d["dates"]})
                    evidence_txt = " | ".join(
                        f"{str(dt)[5:10]}: {exp[:80]}"
                        for dt, exp in d["evidence"][-3:])  # 最近3条证据
                    ws.execute("""
                        INSERT OR REPLACE INTO risk_memory
                        (employee_id, scenario, first_seen, last_seen, total_events,
                         total_alerts, peak_score, recent_score, trend, evidence_summary,
                         episode_count, days_active, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (emp, scen,
                          d["dates"][0], d["dates"][-1],
                          d["verdict_count"], d["alert_count"],
                          max(d["scores"]), d["scores"][-1],
                          _trend(d["scores"]), evidence_txt,
                          _episodes(d["dates"]), days,
                          bj_now()))
                ws.commit()
            finally:
                ws.close()
        return len(agg)
    finally:
        s.close()


def memory_for_llm(emp: str) -> str:
    """该员工的风险记忆摘要(喂给研判AI)——让AI看到完整风险轨迹而非孤立事件。"""
    import sqlite3
    try:
        db = sqlite3.connect("/app/data/ipguard.db", timeout=30)
        db.row_factory = sqlite3.Row
        rows = db.execute("""
            SELECT * FROM risk_memory WHERE employee_id=? AND total_events >= 2
            ORDER BY last_seen DESC LIMIT 5""", (emp,)).fetchall()
        if not rows:
            return ""
        parts = []
        for r in rows:
            trend_cn = {"rising": "↑上升", "falling": "↓下降", "stable": "→稳定"}.get(r["trend"], "")
            scen_cn = {"data_exfiltration": "数据外发", "policy_violation": "违规",
                      "job_seeking": "求职", "baseline_deviation": "行为偏离"}.get(r["scenario"], r["scenario"])
            parts.append(
                f"[{scen_cn}] 首次{str(r['first_seen'])[:10]}~最近{str(r['last_seen'])[:10]}, "
                f"累计{r['total_events']}次研判/{r['total_alerts']}条告警, "
                f"峰值{r['peak_score']}分/近期{r['recent_score']}分{trend_cn}, "
                f"活跃{r['days_active']}天/{r['episode_count']}个活跃期")
        db.close()
        return "\n【风险记忆】该员工历史行为档案(结合当前窗口综合判断,风险轨迹而非孤立事件):\n" + "\n".join(parts)
    except Exception:
        return ""


def get_memory_api():
    """API: 全部员工的风险记忆(画像页展示用)。"""
    import sqlite3
    try:
        db = sqlite3.connect("/app/data/ipguard.db", timeout=30)
        db.row_factory = sqlite3.Row
        rows = db.execute("""
            SELECT rm.*, COUNT(a.id) current_alerts
            FROM risk_memory rm
            LEFT JOIN alerts a ON a.employee_id = rm.employee_id
                AND a.scenario = rm.scenario AND a.status = 'NEW'
            GROUP BY rm.employee_id, rm.scenario
            ORDER BY rm.peak_score DESC, rm.last_seen DESC
            LIMIT 100""").fetchall()
        db.close()
        return [dict(r) for r in rows]
    except Exception:
        return []
