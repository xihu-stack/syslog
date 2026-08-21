"""离职综合风险榜(2026-08-21): 多信号组合→单人一分数,全公司一张屏。

信号权重(2026-08-21设计,可调):
  招聘访问(≥50分研判/告警)  30%
  文档外发(SEND/UPLOAD到非白名单)  25%
  大量删除(mass_delete告警)  20%
  离职搜索(AI判定的求职搜索)  15%
  节律突变(深夜活跃天数突增)  10%
组合规则: 单一信号→观察;2类→关注;3类→预警;4类+→高危。
与storyline的关系: storyline是R1深度叙事,本模块是程序化即时计算(无LLM调用,秒出)。
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from db import Session, EventRow, VerdictRow, AlertRow, ProfileRow, bj_now
import dicts
import detector


def risk_board(days: int = 7) -> list:
    s = Session()
    try:
        since = bj_now() - timedelta(days=days)
        sig = defaultdict(lambda: {"job": 0, "exfil": 0, "delete": 0, "search": 0, "night": 0, "detail": {}})

        # 1) 招聘信号
        for v in s.query(VerdictRow).filter(
                VerdictRow.window_start >= since, VerdictRow.intent == "job_seeking",
                VerdictRow.risk_score >= 50).all():
            sig[v.employee_id]["job"] = max(sig[v.employee_id]["job"], v.risk_score)
            sig[v.employee_id]["detail"]["job"] = f"招聘研判{v.risk_score}分"

        # 2) 外发信号
        for a in s.query(AlertRow).filter(
                AlertRow.created_at >= since, AlertRow.scenario == "data_exfiltration").all():
            sig[a.employee_id]["exfil"] = max(sig[a.employee_id]["exfil"], a.risk_score or 0)
            sig[a.employee_id]["detail"]["exfil"] = f"外发告警{a.risk_score}分"
        # 也看原始事件(无告警但有SEND)
        for e in s.query(EventRow).filter(
                EventRow.source == "ipguard", EventRow.occurred_at >= since,
                EventRow.action.in_(("SEND", "UPLOAD"))).all():
            dest = ((e.raw or {}).get("dest_path") or "").split("/")[0].lower()
            if dest and not any(dest == w or dest.endswith("." + w) for w in dicts.get("risk_whitelist_domains") or []):
                sig[e.employee_id]["exfil"] = max(sig[e.employee_id]["exfil"], 60)
                sig[e.employee_id]["detail"].setdefault("exfil", "有非白名单外发行为")

        # 3) 大量删除
        for a in s.query(AlertRow).filter(
                AlertRow.created_at >= since, AlertRow.scenario == "mass_delete").all():
            sig[a.employee_id]["delete"] = a.risk_score or 70
            sig[a.employee_id]["detail"]["delete"] = f"删除{a.risk_score}分"

        # 4) 搜索信号(SEARCH事件中有AI判为job_seeking的)
        for v in s.query(VerdictRow).filter(
                VerdictRow.window_start >= since, VerdictRow.intent == "job_seeking",
                VerdictRow.risk_score >= 30).all():  # 降低门槛,30+的求职搜索也算
            if "搜索" in (v.explanation or "") or "简历" in (v.explanation or ""):
                sig[v.employee_id]["search"] = max(sig[v.employee_id]["search"], v.risk_score)
                sig[v.employee_id]["detail"]["search"] = "有求职相关搜索"

        # 5) 节律突变(深夜活跃天数 vs 前一周)
        for p in s.query(ProfileRow).all():
            emp = p.employee_id
            if emp not in sig:
                continue
            rh = (p.payload or {}).get("rhythm") if isinstance(p.payload, dict) else None
            if rh and (rh.get("late_night_days") or 0) >= 3:
                sig[emp]["night"] = 50
                sig[emp]["detail"]["night"] = f"深夜活跃{rh['late_night_days']}天"

        # 组合计算
        board = []
        for emp, s2 in sig.items():
            types = sum(1 for k in ("job", "exfil", "delete", "search", "night") if s2[k] > 0)
            # 加权分
            score = (s2["job"] * 0.30 + s2["exfil"] * 0.25 + s2["delete"] * 0.20 +
                     s2["search"] * 0.15 + s2["night"] * 0.10)
            # 信号种类加成(多信号组合比单信号强)
            score += (types - 1) * 8 if types > 1 else 0
            score = min(int(score), 100)
            stage = "高危" if types >= 4 or score >= 80 else \
                   "预警" if types >= 3 or score >= 65 else \
                   "关注" if types >= 2 or score >= 45 else "观察"
            board.append({"employee": emp, "score": score, "stage": stage,
                          "signals": types, "detail": s2["detail"],
                          "breakdown": {k: v for k, v in s2.items() if k != "detail" and v > 0}})
        board.sort(key=lambda x: -x["score"])
        return board[:30]
    finally:
        s.close()
