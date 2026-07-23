"""行为画像构建：从 events 滚动统计每员工基线，喂给 LLM 做偏离判断。

v1 用轻量统计（活跃时段/日均量/常用通道/常接触关键词），不上重型 ML。
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from statistics import median

from db import EventRow, ProfileRow, Session
import dicts  # 敏感词表改为从字典配置读取

LOOKBACK_DAYS = 30


def _events_for(session, emp):
    since = datetime.utcnow() - timedelta(days=LOOKBACK_DAYS)
    return (session.query(EventRow)
            .filter(EventRow.employee_id == emp, EventRow.occurred_at >= since)
            .all())


def compute_profile(rows) -> dict:
    hours = Counter()
    per_day = Counter()
    web_classes = Counter()
    domains = Counter()
    channels, actions, keywords = set(), set(), set()
    for r in rows:
        hours[r.occurred_at.hour] += 1
        per_day[r.occurred_at.date()] += 1
        ch = (r.raw or {}).get("channel")
        if ch:
            channels.add(ch)
        if r.category == "WEB":
            d = (r.raw or {}).get("domain")
            if d:
                domains[d] += 1
            dc = (r.raw or {}).get("domain_class")
            if dc and dc != "other":
                web_classes[dc] += 1
        actions.add(r.action)
        for k in dicts.get("sensitive_keywords"):
            if k in (r.target_value or ""):
                keywords.add(k)
    daily = list(per_day.values())
    return {
        "active_hours_top": [h for h, _ in hours.most_common(8)],
        "daily_doc_op_median": int(median(daily)) if daily else 0,
        "daily_doc_op_max": max(daily) if daily else 0,
        "channels_used": sorted(channels),
        "web_classes": dict(web_classes),
        "common_domains": [d for d, _ in domains.most_common(20)],
        "actions_seen": sorted(actions),
        "usual_keywords": sorted(keywords),
        "sample_count": len(rows),
    }


def baseline_for(session, employee_id: str, cutoff) -> dict:
    """该员工 cutoff 之前的历史行为基线——用于研判当前窗口是否偏离。"""
    rows = (session.query(EventRow).filter(EventRow.employee_id == employee_id,
            EventRow.occurred_at < cutoff).all())
    return compute_profile(rows)


def summarize_for_llm(p: dict) -> str:
    """把画像压缩成一句给 LLM 看的基线摘要。"""
    if not p or p.get("sample_count", 0) < 3:
        return "（样本不足，按通用可疑度判断）"
    ch = "/".join(p["channels_used"]) or "?"
    kw = ",".join(p["usual_keywords"][:6]) or "无"
    hrs = p["active_hours_top"]
    hrange = f"{min(hrs)}-{max(hrs)}" if hrs else "?"
    wc = p.get("web_classes", {})
    web_txt = ("；网页偏好 " + "/".join(f"{k}:{v}" for k, v in wc.items())) if wc else ""
    return (f"活跃时段约 {hrange} 点；日均活动 ~{p['daily_doc_op_median']}"
            f"(峰值 {p['daily_doc_op_max']})；常用通道 {ch}{web_txt}；常接触关键词[{kw}]；"
            f"是否用过USB={'是' if 'USB' in p['channels_used'] else '否'}")


def build_profiles() -> int:
    """全量重建所有员工画像，返回员工数。按 employee_id 唯一键 upsert。"""
    s = Session()
    try:
        emps = [r[0] for r in s.query(EventRow.employee_id).distinct()]
        now = datetime.utcnow()
        for emp in emps:
            p = compute_profile(_events_for(s, emp))
            existing = s.query(ProfileRow).filter_by(employee_id=emp).first()
            if existing:
                existing.as_of = now
                existing.payload = p
            else:
                s.add(ProfileRow(employee_id=emp, as_of=now, payload=p))
        s.commit()
        return len(emps)
    finally:
        s.close()
