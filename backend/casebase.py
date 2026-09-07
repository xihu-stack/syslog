# -*- coding: utf-8 -*-
"""案例库(AI灵魂一期,2026-09-04): 行为级判例的建档/检索/注入。
路由边界(spec): 代码管事实,语义归AI,案例库管口径对齐——本模块只做结构键
检索(纯Python加权评分,不用向量),不参与打分。所有入口 fail-soft:
调用方主流程不受案例失败影响(record_case内部吞异常,similar/cases返回空)。
"""
import hashlib
import json
import threading
import time
from datetime import timedelta

from db import CaseRow, Session, bj_now, events_by_hashes, write_lock
import dicts

ATTRIBUTIONS = ("域名定性错", "意图错", "程度夸大", "时段可豁免", "通道误判")


def feature_keys_of(window, verdict: dict) -> dict:
    """窗口+结论 → 结构键。域名类集=窗口内域名经dicts.risk_class归类的非空类去重;
    行为集=category:action去重;时段=含非工作时段(0-6/22-23,与研判同口径);
    量级=事件数档位。归一化=同口径行为跨员工跨意图得到同名键。"""
    doms = set()
    for e in window:
        raw = e.raw if isinstance(e.raw, dict) else {}
        d = str(raw.get("domain") or e.target_value or "").lower().split("/")[0].split(":")[0]
        c = dicts.risk_class(d) if d else None
        if c:
            doms.add(c)
    acts = {f"{e.category}:{e.action}" for e in window}
    hours = [e.occurred_at.hour for e in window if e.occurred_at]
    n = len(window)
    return {"intent": (verdict or {}).get("intent") or "unknown",
            "dom_classes": sorted(doms),
            "actions": sorted(acts),
            "off_hours": bool(hours and (min(hours) < 7 or max(hours) >= 22)),
            "volume": "1" if n <= 1 else ("2-5" if n <= 5 else "6+")}


def behavior_key(fk: dict) -> str:
    """结构键 → 行为口径hash(12位hex): 同口径=同名键,跨员工复用的锚。"""
    core = {k: (fk or {}).get(k) for k in ("intent", "dom_classes", "actions", "off_hours", "volume")}
    return hashlib.sha1(json.dumps(core, ensure_ascii=False, sort_keys=True)
                        .encode("utf-8")).hexdigest()[:12]


def score_similarity(a: dict, b: dict) -> int:
    """加权评分(满分100): intent同=40 域名类集Jaccard=30 行为集Jaccard=20
    时段同=5 量级同=5。空集双方Jaccard记0(无证据不加分)。"""
    sc = 0
    if a.get("intent") and a.get("intent") == b.get("intent"):
        sc += 40  # intent缺省(unknown/None)=无证据,不计同(否则空对空=40分会假命中)
    for k, w in (("dom_classes", 30), ("actions", 20)):
        sa, sb = set(a.get(k) or []), set(b.get(k) or [])
        if sa or sb:
            sc += int(w * len(sa & sb) / len(sa | sb))
    if bool(a.get("off_hours")) == bool(b.get("off_hours")):
        sc += 5
    if a.get("volume") == b.get("volume"):
        sc += 5
    return sc


def is_hard(intent, score: int, threshold: int = 50) -> bool:
    """难例判定(spec一期): |score-threshold|≤15 或 意图unknown。
    spec另提的"复核摇摆"留二期——复核分歧信号在_judge内部,需先暴露才能判。"""
    return intent in (None, "", "unknown") or abs((score or 0) - threshold) <= 15


def record_case(source, employee_id, outcome, attribution="", verdict_row=None,
                note="", fk=None, ai_verdict="") -> bool:
    """建档+去重(同behavior_key近30天只留最新outcome→更新旧行,spec口径)。
    verdict_row给出时自动重建窗口提facts_digest/feature_keys/ai_verdict;
    显式fk/ai_verdict可覆盖(测试/sampleaudit路径)。全异常吞掉打日志。"""
    try:
        digest, ai_v = "", ai_verdict
        if fk is None:
            fk = {}
            if verdict_row is not None:
                _sr = Session()
                try:
                    evs = sorted(events_by_hashes(_sr, (verdict_row.event_hashes or [])[:400]),
                                 key=lambda x: x.occurred_at)
                finally:
                    _sr.close()
                from models import CanonicalEvent
                win = [CanonicalEvent(occurred_at=r.occurred_at, employee_id=r.employee_id,
                                      device_id=r.device_id, category=r.category, action=r.action,
                                      target_type=r.target_type or "FILE",
                                      target_value=r.target_value or "",
                                      size_bytes=r.size_bytes or 0, count=r.count or 1,
                                      source=r.source or "", raw=r.raw or {}) for r in evs]
                from daygate import _digest
                digest = _digest(win)[:600]
                ai_v = ai_v or f"{verdict_row.intent}/{verdict_row.risk_score}: {str(verdict_row.explanation)[:200]}"
                fk = feature_keys_of(win, {"intent": verdict_row.intent})
        bk = behavior_key(fk)
        with write_lock:
            ss = Session()
            try:
                old = ss.query(CaseRow).filter(
                    CaseRow.behavior_key == bk,
                    CaseRow.created_at >= bj_now() - timedelta(days=30)).first()
                if old:
                    old.outcome = outcome or old.outcome
                    old.attribution = attribution or old.attribution
                    old.source = source or old.source
                    old.created_at = bj_now()
                else:
                    ss.add(CaseRow(source=source, employee_id=employee_id,
                                   intent=(fk.get("intent") or ""), behavior_key=bk,
                                   outcome=outcome, attribution=attribution,
                                   facts_digest=digest, feature_keys=fk, ai_verdict=ai_v,
                                   delta=(note or "")[:400],
                                   verdict_id=getattr(verdict_row, "id", None)))
                ss.commit()
            finally:
                ss.close()
        return True
    except Exception as e:
        print(f"[casebase] 入库失败(不影响主流程): {e}", flush=True)
        return False


def similar_cases(fk: dict, top: int = 5) -> list:
    """按结构键加权评分取top(近30天,python侧评分;≥40分才入选——低于=intent
    与域名类都不同,不是同口径行为)。"""
    try:
        s = Session()
        try:
            since = bj_now() - timedelta(days=30)
            rows = s.query(CaseRow).filter(CaseRow.created_at >= since).all()
            scored = sorted(((score_similarity(fk, r.feature_keys or {}), r) for r in rows),
                            key=lambda x: -x[0])
            return [r for sc, r in scored[:top] if sc >= 40]
        finally:
            s.close()
    except Exception as e:
        print(f"[casebase] 检索失败(返回空): {e}", flush=True)
        return []


def cases_for_prompt(fk: dict, top: int = 5) -> str:
    """难例注入段(spec: 5条≤800字): 【相似历史案例(人工已复核)】。"""
    rows = similar_cases(fk, top)
    if not rows:
        return ""
    lines = [f"- {str(r.ai_verdict or r.facts_digest or r.behavior_key)[:120]}"
             f" →人工:{r.outcome}" + (f"({r.attribution})" if r.attribution else "")
             for r in rows]
    return ("【相似历史案例(人工已复核)——同口径行为此前的人工结论,判定时对齐】\n"
            + "\n".join(lines)[:800] + "\n")


_CALIBER_CACHE = {"txt": "", "ts": 0.0}
_CALIBER_LOCK = threading.Lock()


def caliber_text() -> str:
    """【人工口径】段(所有AI通道共享,spec口径统一注入——italent事故架构修复):
    白名单口径(人工字典真源渲染) + 近30天高频误报判例(behavior_key去重取8条)。
    进程内TTL 10min缓存——字节级稳定,vLLM prefix caching才能命中共享前缀;
    新判例/字典改动10min内自然生效,不必重启。"""
    with _CALIBER_LOCK:
        if _CALIBER_CACHE["txt"] and time.time() - _CALIBER_CACHE["ts"] < 600:
            return _CALIBER_CACHE["txt"]
    parts = []
    wl = [w for w in (dicts.get("risk_whitelist_domains") or []) if w]
    if wl:
        parts.append("【人工口径——公司确认的例外(优先级最高,覆盖其他规则)】以下域名及其子域"
                     "=公司白名单通道/系统,一律正常办公,严禁判成风险或写进风险说明: "
                     + ", ".join(wl[:40]) + "。")
    try:
        s = Session()
        try:
            since = bj_now() - timedelta(days=30)
            rows = (s.query(CaseRow)
                    .filter(CaseRow.created_at >= since, CaseRow.outcome == "false_positive")
                    .order_by(CaseRow.created_at.desc()).limit(60).all())
            seen, picks = set(), []
            for r in rows:
                if r.behavior_key not in seen:
                    seen.add(r.behavior_key)
                    picks.append(r)
            lines = [f"- {str(r.ai_verdict or '')[:80]} →人工:误报"
                     + (f"({r.attribution})" if r.attribution else "")
                     + ((f" {str(r.delta)[:60]}") if r.delta else "")
                     for r in picks[:8] if str(r.ai_verdict or r.facts_digest or "").strip()]
            if lines:
                parts.append("【人工口径——已复核误报判例(同类行为不得再判风险)】\n" + "\n".join(lines))
        finally:
            s.close()
    except Exception:
        pass  # 案例读失败=只给白名单段(fail-soft)
    txt = ("\n" + "\n".join(parts)) if parts else ""
    with _CALIBER_LOCK:
        _CALIBER_CACHE.update(txt=txt, ts=time.time())
    return txt
