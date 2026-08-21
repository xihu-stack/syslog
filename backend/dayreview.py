"""N+1 日复核(2026-08-21设计定稿): 次日凌晨用R1回看昨天全天视野,修正实时结论。

定位(与N+0/N+7的分工):
  N+0 实时——60分钟窗,快而近视,允许误差,负责预警;
  N+1 日复核——全天完整事件+昨日实时研判清单,负责修正:升级(散点外发聚成蓄意)
    /降级(孤立事件被全天上下文证明正常,仅标注建议,人保留处置权)/串联因果;
  N+7 周复核——storyline/docscan。

工程约束(2026-08-21首跑教训): 每人独立短事务(读→关→R1→短事务回写),
不持读事务过LLM调用,避免与入库长互等锁死。
回写规则: 升级→分数上调(吸附合法档)+[次日复核↑];降级→仅标注[疑误报];
  已知晓/误报状态永不触碰。
"""
from __future__ import annotations

import json
import re
from collections import Counter
from datetime import timedelta

from db import Session, EventRow, VerdictRow, AlertRow, bj_now
import dicts
import detector
import llm_client

PROMPT = """你是企业行为安全分析师,做"次日复核":输入是某员工昨天(完整一天)的多源行为摘要 + 当天实时研判清单(实时层只看60分钟窗口,可能低估或高测)。
请以全天视野重估,输出 JSON:
{"review": "全天故事结论(150字内,5W+因果:哪些事件相互关联构成模式)",
 "direction": "upgrade|downgrade|keep",
 "suggested_score": 0-100(你认为该员工昨日综合风险分),
 "reason": "与实时结论的差异及依据(一句话)"}
判断口径: 实时层多次触发但单看都不重(如零散外发+删除+招聘访问分散在不同窗口)→upgrade;
实时层的告警在全天下文里是孤立且可解释的正常业务(如单次报销后无后续)→downgrade;
否则keep。只输出JSON。"""

_TIERS = {"policy_violation": {75, 80, 85, 90}, "data_exfiltration": {75, 80, 85, 90},
          "job_seeking": {55, 60, 65, 70, 75, 80, 85, 90, 95}}


def _snap(scen, score):
    tiers = _TIERS.get(scen)
    if not tiers:
        return score
    legal = sorted(x for x in tiers if x >= score)
    return legal[0] if legal else max(tiers)


def _day_bounds(days_ago=1):
    d0 = bj_now() - timedelta(days=days_ago)
    return d0.replace(hour=0, minute=0, second=0, microsecond=0), d0.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)


def _candidates(d0, d1):
    s = Session()
    try:
        cands = set()
        for (e,) in s.query(VerdictRow.employee_id).filter(VerdictRow.window_start >= d0,
                                                           VerdictRow.window_start < d1,
                                                           VerdictRow.risk_score >= 50).all():
            cands.add(e)
        for (e,) in s.query(EventRow.employee_id).filter(
                EventRow.occurred_at >= d0, EventRow.occurred_at < d1,
                EventRow.source == "ipguard",
                EventRow.action.in_(("SEND", "UPLOAD", "DELETE"))).all():
            cands.add(e)
        return sorted(cands)[:20]
    finally:
        s.close()


def _digest(s, emp, d0, d1, day):
    evs = s.query(EventRow).filter(EventRow.employee_id == emp,
                                    EventRow.occurred_at >= d0,
                                    EventRow.occurred_at < d1).all()
    if not evs:
        return None
    lines = [f"员工: {emp} 日期: {day}"]
    web, sends, dels, docs, ks, hrs = Counter(), [], [], [], [], set()
    for e in evs:
        if e.occurred_at:
            hrs.add(e.occurred_at.hour)
        raw = e.raw or {}
        if e.category == "WEB":
            d = (raw.get("domain") or "").lower()
            if dicts.risk_class(d):
                t = (raw.get("title") or "")[:20]
                web[f"{d}×{e.count or 1}《{t}》" if t else f"{d}×{e.count or 1}"] += 1
        elif e.category == "DOC":
            if e.action in ("SEND", "UPLOAD"):
                dest = (raw.get("dest_path") or "").split("/")[0][:30]
                sends.append(f"{(e.target_value or '')[:30]}→{dest or raw.get('channel')}")
            elif e.action == "DELETE" and not detector.is_noise_doc(e):
                dels.append((e.target_value or "")[:30])
            else:
                docs.append(f"{e.action}:{(e.target_value or '')[:24]}")
        elif e.category == "SEARCH" and e.target_value:
            ks.append(e.target_value[:24])
    if web:
        lines.append("[风险网站] " + "; ".join(list(web)[:8]))
    if sends:
        lines.append(f"[外发{len(sends)}次] " + "; ".join(sends[:8]))
    if dels:
        lines.append(f"[删除{len(dels)}个] " + "; ".join(dels[:8]))
    if docs:
        lines.append(f"[其他文档操作{len(docs)}] " + "; ".join(docs[:6]))
    if ks:
        lines.append("[搜索] " + "; ".join(ks[:6]))
    if hrs:
        lines.append(f"[活跃时段] {min(hrs)}-{max(hrs)}时")
    yv = s.query(VerdictRow).filter(VerdictRow.employee_id == emp,
                                    VerdictRow.window_start >= d0,
                                    VerdictRow.window_start < d1).all()
    if yv:
        lines.append("[昨日实时研判] " + "; ".join(
            f"{v.intent}{v.risk_score}分:{(v.explanation or '')[:40]}" for v in yv[:6]))
    return "\n".join(lines)[:8000]


def _writeback(emp, r, d0, d1):
    direction = r.get("direction") or "keep"
    if direction == "keep":
        return
    sug = int(r.get("suggested_score") or 0)
    reason = (r.get("reason") or "")[:80]
    review = (r.get("review") or "")[:160]
    s = Session()
    try:
        for a in s.query(AlertRow).filter(AlertRow.employee_id == emp).all():
            if a.status in ("FP", "CLOSED"):
                continue
            if not (a.window_start and d0 <= a.window_start < d1):
                continue
            sm = re.sub(r"\[次日复核[^\]]*\]\s*", "", a.summary or "")
            if direction == "upgrade" and sug > (a.risk_score or 0) and a.scenario in _TIERS:
                a.risk_score = _snap(a.scenario, sug)
                a.summary = f"[次日复核↑{a.risk_score}分: {reason}] {review} | {sm}"
            elif direction == "downgrade":
                a.summary = f"[次日复核:疑误报——{reason}] {sm}"
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def run_day_review(days_ago: int = 1) -> dict:
    d0, d1 = _day_bounds(days_ago)
    day = str(d0.date())
    cands = _candidates(d0, d1)
    results = {}
    for emp in cands:
        s = Session()
        try:
            digest = _digest(s, emp, d0, d1, day)
        finally:
            s.close()
        if not digest:
            continue
        try:
            raw = llm_client.chat([{"role": "system", "content": PROMPT},
                                   {"role": "user", "content": digest}],
                                  max_tokens=700, timeout=180,
                                  model=llm_client.smart_model() or None)
            txt = llm_client.strip_think(raw)
            i = txt.find("{")
            r = json.loads(txt[i:txt.rfind("}") + 1]) if i >= 0 else {}
        except Exception as ex:
            r = {"review": f"复核失败:{str(ex)[:60]}", "direction": "keep"}
        r["ts"] = bj_now().isoformat()
        results[emp] = r
        try:
            _writeback(emp, r, d0, d1)
        except Exception as ex:
            r["writeback_error"] = str(ex)[:60]
        print(f"[dayreview] {emp}: {r.get('direction')} {r.get('suggested_score')}", flush=True)
    dicts.set_setting("day_reviews", json.dumps(results, ensure_ascii=False))
    return {"day": day, "candidates": len(cands),
            "upgraded": sum(1 for r in results.values() if r.get("direction") == "upgrade"),
            "downgraded": sum(1 for r in results.values() if r.get("direction") == "downgrade")}
