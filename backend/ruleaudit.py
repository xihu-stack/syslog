# -*- coding: utf-8 -*-
"""规则体检(2026-09-07持续性缺口①): 每周给规则自己的成绩单。

进化回路原料(新词/判例/漏报率)都在自动收集,但"哪条规则该改"仍靠个案撞出来。
本模块按风险类聚合近30天 [域名命中→告警→人工处置] 全链路,自动标三类信号:
- high_fp: 已处置≥5条且FP率>30% → 规则过紧(该松/该进白名单/该改prompt口径)
- dead:    类30天零命中 → 死字典(删除或降级候选,白名单化候选)
- drift:   本周命中量>前4周周均×3 → 行为漂移或新人群(该看,不是该改)
纯SQL+字典聚合,不依赖LLM也可跑;AI一句话总结fail-soft。
结果存settings(/api/ruleaudit可查)+webhook推送。周一凌晨由小时维护触发。
"""
import json
from collections import defaultdict
from datetime import timedelta

import dicts
import llm_client
from db import (AlertRow, EventRow, FeedbackRow, Session, VerdictRow,
                bj_now, events_by_hashes, json_field)

WINDOW_DAYS = 30
FP_RATE_GATE = 0.30   # 已处置≥MIN_DISPOSED且FP率超此 → high_fp
MIN_DISPOSED = 5
DRIFT_RATIO = 3.0     # 本周命中 > 前4周周均×此值 → drift
# 应在产生命中的风险类清单(与dicts.risk_patterns类名同源;零命中=死字典)
EXPECTED = ("网盘/云盘", "个人邮箱", "微信文件助手", "远程控制",
            "招聘求职", "代码仓库", "AI助手")


def _collect(s, d0, d1):
    """近30天: 类→{命中桶数,人数,按ISO周命中}; 类→处置{TP,FP}。"""
    by_cls = defaultdict(lambda: {"hits": 0, "people": set(), "weeks": defaultdict(int)})
    dom_expr = json_field(EventRow.raw, "domain")
    rows = s.query(EventRow.employee_id, EventRow.occurred_at, dom_expr).filter(
        EventRow.category == "WEB", EventRow.occurred_at >= d0).yield_per(3000)
    _rc = {}
    for emp, occ, dom in rows:
        d = (dom or "").strip().lower()
        if not d:
            continue
        rc = _rc.get(d)
        if rc is None:
            rc = dicts.risk_class(d) or ""
            _rc[d] = rc
        if not rc:
            continue
        st = by_cls[rc]
        st["hits"] += 1
        if emp:
            st["people"].add(emp)
        if occ:
            st["weeks"][f"{occ.isocalendar()[0]}-W{occ.isocalendar()[1]:02d}"] += 1
    # 处置链: Feedback(TP/FP) → Alert → Verdict.event_hashes → 事件域名 → 类。
    # 一个告警跨多类时每类各记一次(保守: 外发窗里网盘+邮箱并存,两边都算证据)。
    disp = defaultdict(lambda: {"TP": 0, "FP": 0})
    _v_cache = {}
    for f, a in (s.query(FeedbackRow, AlertRow)
                 .join(AlertRow, FeedbackRow.alert_id == AlertRow.id)
                 .filter(AlertRow.window_start >= d0).all()):
        if f.label not in ("TP", "FP") or not a.verdict_id:
            continue
        v = _v_cache.get(a.verdict_id)
        if v is None:
            v = s.query(VerdictRow).get(a.verdict_id)
            _v_cache[a.verdict_id] = v
        if not v or not v.event_hashes:
            continue
        seen = set()
        for e in events_by_hashes(s, v.event_hashes[:50]):
            if e.category != "WEB":
                continue
            d = str(((e.raw or {}).get("domain") or "")).lower().strip()
            rc = _rc.setdefault(d, dicts.risk_class(d) or "") if d else ""
            if rc and rc not in seen:  # 同类去重: 一条告警一类只记一次
                seen.add(rc)
                disp[rc][f.label] += 1
    return by_cls, disp


def _make_flags(by_cls: dict, disp: dict, expected=EXPECTED) -> list:
    """聚合结果→三类信号(纯函数,可单测)。"""
    flags = []
    for cls, st in by_cls.items():
        d = disp.get(cls) or {}
        fp, tp = d.get("FP", 0), d.get("TP", 0)
        disposed = fp + tp
        if disposed >= MIN_DISPOSED and fp / disposed > FP_RATE_GATE:
            flags.append({"type": "high_fp", "cls": cls, "fp": fp,
                          "disposed": disposed,
                          "detail": f"{cls}类已处置{disposed}条中误报{fp}条"
                                    f"(FP率{fp / disposed:.0%}>{FP_RATE_GATE:.0%}),规则过紧"})
        weeks = sorted(st["weeks"].keys())
        if weeks:
            cur = st["weeks"][weeks[-1]]
            hist = [st["weeks"][w] for w in weeks[:-1]]
            if hist and cur > sum(hist) / len(hist) * DRIFT_RATIO and cur >= 10:
                flags.append({"type": "drift", "cls": cls, "hits": cur,
                              "detail": f"{cls}类本周命中{cur}次,达前{len(hist)}周均值的"
                                        f"{cur / (sum(hist) / len(hist)):.1f}倍(行为漂移或新人群)"})
    for cls in expected:
        if cls not in by_cls:
            flags.append({"type": "dead", "cls": cls,
                          "detail": f"{cls}类近{WINDOW_DAYS}天零命中(死字典:删除/降级/白名单化候选)"})
    return flags


def _fmt(by_cls, disp, flags) -> str:
    lines = [f"规则体检(近{WINDOW_DAYS}天按风险类):"]
    for cls in sorted(by_cls, key=lambda c: -by_cls[c]["hits"]):
        st, d = by_cls[cls], disp.get(cls) or {}
        lines.append(f"  {cls}: 命中{st['hits']}次/{len(st['people'])}人"
                     f" 处置TP{d.get('TP', 0)}/FP{d.get('FP', 0)}")
    if flags:
        lines.append("信号:")
        lines += [f"  [{f['type']}] {f['detail']}" for f in flags]
    else:
        lines.append("信号: 无(各类健康)")
    return "\n".join(lines)[:4000]


def run_rule_audit() -> dict:
    """主入口(周一凌晨小时维护/手动API)。LLM失败不阻塞结果落库。"""
    d1 = bj_now()
    d0 = d1 - timedelta(days=WINDOW_DAYS)
    s = Session()
    try:
        by_cls, disp = _collect(s, d0, d1)
    finally:
        s.close()
    stats = {cls: {"hits": st["hits"], "people": len(st["people"]),
                   "weeks": dict(st["weeks"])} for cls, st in by_cls.items()}
    disp_s = {cls: dict(d) for cls, d in disp.items()}
    flags = _make_flags(by_cls, disp)
    # AI一句话建议(fail-soft): 信号已可读,LLM只做归并降噪
    ai = ""
    try:
        ai = llm_client.chat([{"role": "user", "content":
                               "你是企业行为审计系统的规则运营助手。根据下面的规则体检结果,"
                               "用不超过3句话给出本周最值得动手的1-2条规则优化建议"
                               "(优先high_fp;dead类提醒可能是字典漂移;drift只提示观察)。\n"
                               + _fmt(by_cls, disp, flags)}],
                              max_tokens=300, timeout=120)
        ai = llm_client.strip_think(ai).strip()
    except Exception as e:
        print(f"[ruleaudit] AI总结失败(不影响体检): {e}", flush=True)
    res = {"ran_at": d1.isoformat()[:16], "window_days": WINDOW_DAYS,
           "classes": stats, "dispositions": disp_s, "flags": flags, "ai_summary": ai}
    dicts.set_setting("rule_audit_report", json.dumps(res, ensure_ascii=False)[:200000])
    dicts.set_setting("ruleaudit_last", d1.strftime("%Y%m%d"))
    try:
        import pipeline as _pl
        n = {"high_fp": sum(1 for f in flags if f["type"] == "high_fp"),
             "dead": sum(1 for f in flags if f["type"] == "dead"),
             "drift": sum(1 for f in flags if f["type"] == "drift")}
        _pl._notify_webhook("规则体检", 0,
                            f"本周规则体检: 活跃类{len(by_cls)}个, 信号: 过紧{n['high_fp']}/"
                            f"死字典{n['dead']}/漂移{n['drift']}。"
                            + ("; ".join(f["detail"] for f in flags[:3]))
                            + ("。" + ai[:120] if ai else "")
                            + "(详情GET /api/ruleaudit)")
    except Exception as e:
        print(f"[ruleaudit] webhook推送失败: {e}", flush=True)
    print(f"[ruleaudit] 体检完成: 类{len(by_cls)} 信号{len(flags)}", flush=True)
    return res


if __name__ == "__main__":
    print(run_rule_audit())
