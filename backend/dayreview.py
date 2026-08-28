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

from db import Session, EventRow, VerdictRow, AlertRow, bj_now, severity_of
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

_TIERS = {"policy_violation": {75, 80, 85, 90}, "data_exfiltration": {75, 80, 85, 90, 95},
          "job_seeking": {55, 60, 65, 70, 75, 80, 85, 90, 95}}


def _snap(scen, score):
    tiers = _TIERS.get(scen)
    if not tiers:
        return score
    legal = sorted(x for x in tiers if x >= score)
    return legal[0] if legal else max(tiers)


def _snap_down(scen, score):
    """降档吸附(2026-08-28): 降分路径吸附到≤该分的最近合法档,与升级路径
    _snap(向上吸)对称——否则出现78分非档位分却挂CRITICAL徽章(运营审计A5)。"""
    tiers = _TIERS.get(scen)
    if not tiers:
        return score
    legal = sorted((x for x in tiers if x <= score), reverse=True)
    return legal[0] if legal else score


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
        # 当日仍有未处理告警的员工也必须复核(2026-08-24): 否则重判后研判缺失的
        # 老告警永远没有候选触发,卡在NEW成为僵尸积压
        for (e,) in s.query(AlertRow.employee_id).filter(
                AlertRow.window_start >= d0, AlertRow.window_start < d1,
                AlertRow.status == "NEW").all():
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
    web_domains = []
    for e in evs:
        if e.occurred_at:
            hrs.add(e.occurred_at.hour)
        raw = e.raw or {}
        if e.category == "WEB":
            d = (raw.get("domain") or "").lower()
            if d:
                web_domains.append((e.occurred_at, d))
            if dicts.risk_class(d):
                t = (raw.get("title") or "")[:20]
                web[f"{d}×{e.count or 1}《{t}》" if t else f"{d}×{e.count or 1}"] += 1
        elif e.category == "DOC":
            if e.action in ("SEND", "UPLOAD"):
                dest = dicts.dest_host(raw)[:30]
                # 同期浏览(±5分钟)域名样例(2026-08-26朱亮案例: 深信服延迟7分钟批量推,
                # N+0时刻看不到目的地,N+1全天视野能看到——让R1说清"传去了哪")
                _near = sorted({(w2[1] or "")[:30] for w2 in web_domains
                                if abs((w2[0] - e.occurred_at).total_seconds()) <= 300
                                and not ((w2[1] or "").startswith(("ws.", "statistic.", "stat.", "log.")))})[:3]
                _nt = f" [同期浏览:{'/'.join(_near)}]" if (_near and not dest) else ""
                sends.append(f"{(e.target_value or '')[:30]}→{dest or '未识别(网页上传)'}{_nt}")
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


def _thin(sm: str) -> bool:
    """薄说明判定(2026-08-26): 长度不足/无通道词/半成品箭头/无具体对象。"""
    sm = sm or ""
    return (len(sm) < 60 or "→;" in sm or "→→" in sm
            or not any(k in sm for k in ("通过", "经", "exe"))
            or ("『" not in sm and "×" not in sm and "访问" not in sm))


def _factual_rewrite(s, emp, d0, d1, direction, reason):
    """用全天事件事实重写说明(2026-08-26优化3): 目的地/文件/次数取自现已完整的数据,
    深信服延迟批在N+0时刻看不到的信息这里都能补上。"""
    from collections import Counter as _C
    sends, downs, doms = [], 0, _C()
    for e in s.query(EventRow).filter(EventRow.employee_id == emp,
                                       EventRow.occurred_at >= d0, EventRow.occurred_at < d1).all():
        raw = e.raw or {}
        if e.category == "DOC" and e.action in ("SEND", "UPLOAD"):
            dh = dicts.dest_host(raw)[:30] or "未识别(网页上传)"
            sends.append("『%s』→%s" % ((e.target_value or "未命名")[:32], dh))
        elif e.category == "DOC" and e.action in ("DOWNLOAD", "RECV"):
            downs += 1
        elif e.category == "WEB":
            d = (raw.get("domain") or "").lower()
            if d and dicts.risk_class(d):
                doms[d] += e.count or 1
    day = str(d0)[5:10]
    parts = []
    if sends:
        parts.append("全天外发%d次: %s%s" % (len(sends), ";".join(sends[:4]), "…" if len(sends) > 4 else ""))
    if downs:
        parts.append("另有下载/接收%d次(方向为收,不计入外发)" % downs)
    if doms:
        parts.append("风险访问: " + "、".join("%s×%d" % (d, n) for d, n in doms.most_common(3)))
    body = ";".join(parts) if parts else "全天无明显风险行为"
    tag = {"upgrade": "全天复核升级", "keep": "全天复核维持"}.get(direction, "全天复核")
    return "[%s|事实重写] %s在%s %s (%s)" % (tag, emp, day, body, (reason or "")[:40])


def _writeback(emp, r, d0, d1):
    direction = r.get("direction") or "keep"
    s = Session()
    try:
        # ③(2026-08-28运营审计) 主导场景: 建议分只作用于当日最高风险研判对应
        # 场景的告警行。原先对当窗所有行统一改分——job_seeking行被写上外发
        # 升级理由的95分(2026-08-28审计案例),模式告警(mass_exfil等无对应
        # 研判意图)也被误降分。非主导行只标注已复核,分数不动。
        dom = None
        vs = s.query(VerdictRow).filter(VerdictRow.employee_id == emp,
                                        VerdictRow.window_start >= d0,
                                        VerdictRow.window_start < d1).all()
        if vs:
            dom = max(vs, key=lambda x: x.risk_score or 0).intent
        if direction == "keep":
            # 维持原判也标注(2026-08-21用户口径: 今日前的告警都应是复核过的,
            # 不能全挂'实时'标签)——轻量前缀,不带理由长文
            for a in s.query(AlertRow).filter(AlertRow.employee_id == emp).all():
                if a.status in ("FP", "CLOSED"):
                    continue
                if not (a.window_start and d0 <= a.window_start < d1):
                    continue
                sm = (a.summary or "")
                if _thin(sm):  # 薄说明→全天事实重写(保留复核痕迹)
                    a.summary = _factual_rewrite(s, emp, d0, d1, "keep", r.get("reason") or "")
                elif not sm.startswith("[次日复核"):
                    a.summary = f"[次日复核:维持] {sm}"
            s.commit()
            return
        sug = int(r.get("suggested_score") or 0)
        reason = (r.get("reason") or "")[:80]
        for a in s.query(AlertRow).filter(AlertRow.employee_id == emp).all():
            if a.status in ("FP", "CLOSED"):
                continue
            if not (a.window_start and d0 <= a.window_start < d1):
                continue
            sm = re.sub(r"\[次日复核[^\]]*\]\s*", "", a.summary or "")
            if dom is not None and a.scenario != dom:
                # 非主导场景行: 只留复核痕迹,不改分不改结论
                if not sm.startswith("[次日复核"):
                    a.summary = f"[次日复核:维持] {sm}"
                continue
            if direction == "upgrade" and sug > (a.risk_score or 0) and a.scenario in _TIERS:
                a.risk_score = _snap(a.scenario, sug)
                a.severity = severity_of(a.risk_score)  # ⑦(2026-08-28): 分数升级必须同步severity,否则85分挂MEDIUM徽章
                a.summary = f"[次日复核↑{a.risk_score}分] " + _factual_rewrite(s, emp, d0, d1, "upgrade", reason)
            elif direction == "downgrade":
                # 2026-08-24 用户口径: N+1复核发现误报 → 自动关闭(不用人工确认)
                # 行为持续 → 保留告警(keep方向处理)
                if sug < 50:
                    a.status = "CLOSED"
                    a.risk_score = sug  # 徽章分同步复核分,否则"75分+已关闭"自相矛盾
                    a.severity = severity_of(sug)
                    a.summary = f"[N+1复核:误报自动关闭——{reason}] {sm}"
                    print(f"[dayreview] 自动关闭: {emp}/{a.scenario} {a.risk_score}->{sug}分", flush=True)
                else:
                    a.summary = f"[次日复核:疑误报——{reason}] {sm}"
                    # 分数仍>=50: 对齐但不关闭(保留人工决策权);吸附到≤该分的
                    # 合法档(2026-08-28),与升级路径对称
                    a.risk_score = _snap_down(a.scenario, min(a.risk_score or 0, sug))
                    a.severity = severity_of(a.risk_score)
            else:
                # upgrade但建议分未超过当前分/非锚点场景: 也标注已复核,
                # 否则"复核过但无痕迹"(2026-08-24潘利锋/高聪案例)
                a.summary = f"[次日复核:维持] {sm}"
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
