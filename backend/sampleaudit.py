# -*- coding: utf-8 -*-
"""抽样审计+漏报率(2026-09-04治本③): 沉默人群召回的可观测测量。

①(域名活表)和②(日级门控)上线后,残余漏报还有多少?没有数字就只能靠
个案复盘驱动调优。本模块每天从昨日"零研判"的沉默员工里随机抽2-8人,
不经过任何预筛直接立桩(model=sampleaudit)交sweep深判——测的是全链路
(规则+①+②)对沉默人群的真实漏检面: 深判翻出≥50分=没人拦住的漏报,
按正常告警处置;结论次日回填sample_audit表,/api/system/stats的
miss_audit字段+大屏"抽样漏报率"给出滚动30天数字,字典/门控每次调优
都有对照,不再靠感觉。
"""
import random
from datetime import datetime, timedelta

from sqlalchemy import func

from db import EventRow, SampleAuditRow, Session, VerdictRow, bj_now, write_lock
import dicts
from daygate import MIN_EVENTS, _pick_hashes

SAMPLE_MIN = 2
SAMPLE_MAX = 8
SAMPLE_RATE = 0.05       # 沉默员工的5%(上下限钳制)
FLAG_SCORE = 50          # 与研判→告警阈值同口径
BACKFILL_HOURS = 6       # 立桩6小时后回填结论(sweep最迟1小时判完,留裕量)


def run_sample_audit() -> dict:
    """主入口(syslog_recv每天hour>=4调用一次)。"""
    d1 = bj_now().replace(hour=0, minute=0, second=0, microsecond=0)
    d0 = d1 - timedelta(days=1)
    day = d0.date().isoformat()
    res = {"day": day, "silent": 0, "sampled": 0}
    s = Session()
    try:
        from pipeline import _ignored_employees
        judged = {e for (e,) in s.query(VerdictRow.employee_id).filter(
            VerdictRow.window_start >= d0, VerdictRow.window_start < d1).all()}
        ignored = _ignored_employees()
        rows = s.query(EventRow.employee_id, func.count(EventRow.id)).filter(
            EventRow.occurred_at >= d0, EventRow.occurred_at < d1
        ).group_by(EventRow.employee_id).all()
        silent = [emp for emp, n in rows
                  if n >= MIN_EVENTS and emp not in judged and emp not in ignored]
        res["silent"] = len(silent)
        random.shuffle(silent)
        k = max(SAMPLE_MIN, min(SAMPLE_MAX, round(len(silent) * SAMPLE_RATE))) if silent else 0
        for emp in silent[:k]:
            if s.query(SampleAuditRow).filter_by(day=day, employee_id=emp).first():
                continue  # 当日已抽过(重跑幂等)
            evs = s.query(EventRow).filter(EventRow.employee_id == emp,
                                           EventRow.occurred_at >= d0,
                                           EventRow.occurred_at < d1
                                           ).order_by(EventRow.occurred_at).all()
            hashes = _pick_hashes(evs)
            if not hashes:
                continue
            with write_lock:
                ss = Session()
                try:
                    if not ss.query(VerdictRow).filter_by(
                            employee_id=emp, window_start=evs[0].occurred_at).first():
                        ss.add(VerdictRow(
                            employee_id=emp, device=evs[0].device_id,
                            window_start=evs[0].occurred_at, window_end=evs[-1].occurred_at,
                            intent="unknown", risk_score=0,
                            explanation="[抽样审计] 随机抽检沉默人群,待sweep深判(测漏报率)",
                            ai_participated=0, event_hashes=hashes, model="sampleaudit"))
                        ss.add(SampleAuditRow(day=day, employee_id=emp))
                        ss.commit()
                        res["sampled"] += 1
                finally:
                    ss.close()
        backfill(s)
        if res["sampled"] > 0 or res["silent"] == 0:
            dicts.set_setting("sampleaudit_last", bj_now().strftime("%Y%m%d"))
    finally:
        s.close()
    return res


def backfill(s) -> int:
    """回填结论: 立桩超6小时的样本取当日AI研判最高分;超7天仍无AI研判(LLM
    长中断, sweep已过7天窗)记'未判'封口,防pending无限堆积。返回回填数。"""
    now = bj_now()
    pend = s.query(SampleAuditRow).filter(SampleAuditRow.outcome_intent.is_(None),
                                          SampleAuditRow.sampled_at < now - timedelta(hours=BACKFILL_HOURS)).all()
    n = 0
    for r in pend:
        if now - r.sampled_at > timedelta(days=7):
            r.outcome_intent, r.outcome_score = "未判(LLM中断)", 0
            n += 1
            continue
        try:
            d0 = datetime.strptime(r.day, "%Y-%m-%d")
        except Exception:
            continue
        best = s.query(VerdictRow).filter(
            VerdictRow.employee_id == r.employee_id,
            VerdictRow.window_start >= d0, VerdictRow.window_start < d0 + timedelta(days=1),
            VerdictRow.ai_participated == 1).order_by(VerdictRow.risk_score.desc()).first()
        if not best:
            continue  # sweep还没判,下轮再看
        r.outcome_intent, r.outcome_score = best.intent, best.risk_score or 0
        n += 1
    if n:
        with write_lock:
            s.commit()
    return n


def miss_rate_summary(s) -> dict:
    """近30天滚动漏报率(大屏miss_audit字段)。flagged=深判≥50分且非normal/unknown。"""
    since = (bj_now() - timedelta(days=30)).date().isoformat()
    rows = s.query(SampleAuditRow).filter(SampleAuditRow.day >= since).all()
    judged = [r for r in rows if r.outcome_intent]
    flagged = [r for r in judged if (r.outcome_score or 0) >= FLAG_SCORE
               and r.outcome_intent not in ("normal_work", "unknown", "未判(LLM中断)")]
    return {"sampled": len(rows), "judged": len(judged), "flagged": len(flagged),
            "rate": round(len(flagged) / len(judged) * 100, 1) if judged else None,
            "pending": len(rows) - len(judged),
            "last_flagged": "; ".join(f"{r.employee_id}:{r.outcome_intent}{r.outcome_score}"
                                      for r in flagged[-3:])}


if __name__ == "__main__":
    print(run_sample_audit())
