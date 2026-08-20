"""系统自检自愈(每小时维护调用)。

固化2026-08-19/20连续审计中用户发现的所有问题类型为不变量,自动巡检+修复。
不变量清单(每条都源于真实案例):
  I1 告警场景必须与研判窗口证据一致(万亮: job告警窗口全是AI域名)
  I2 告警分=研判分, verdict_id不悬空(告警挂在被删/改意图的研判上)
  I3 豁免场景无告警行, 豁免研判带[已豁免]前缀(展佳: HR豁免后研判高分可见)
  I4 求职研判窗口必须含招聘域名(纯AI窗口被当日累计裹挟)
  I5 无窗口证据但近7天有真实行为的告警→改写说明保留; 完全无据→关闭
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta

import dicts
from db import AlertRow, EventRow, ExceptionRow, Session, VerdictRow, bj_now

_DOC_W = ("COPY", "MOVE", "DELETE", "UPLOAD", "SEND", "PRINT", "BURN")
_SIG = {"policy_violation": ("网盘/云盘", "个人邮箱"),
        "data_exfiltration": ("微信文件助手", "网盘/云盘", "个人邮箱")}
_ANCHOR_TIERS = {"policy_violation": {75, 80, 85, 90},
                 "data_exfiltration": {75, 80, 85, 90},
                 "job_seeking": {55, 60, 65, 70, 75, 80, 85, 90, 95}}


def _verdict_sig(s, v):
    hs = v.event_hashes or []
    evs = s.query(EventRow).filter(EventRow.event_hash.in_(hs)).all() if hs else []
    sig = Counter()
    for e in evs:
        if e.category == "DOC" and e.action in _DOC_W:
            sig["DOC写"] += 1
        elif e.category == "WEB":
            rc = dicts.risk_class(((e.raw or {}).get("domain") or "").lower())
            if rc:
                sig[rc] += (e.count or 1)
    return sig, evs


def selfcheck() -> dict:
    fixes = []
    s = Session()
    try:
        # 豁免表
        exc = defaultdict(dict)
        for x in s.query(ExceptionRow).all():
            exc[x.employee_id][x.signal_type] = x.reason or "岗位需要"

        # ---- I3: 豁免场景的告警行删除 + 研判补标注 ----
        for a in s.query(AlertRow).all():
            if a.scenario in (exc.get(a.employee_id) or {}):
                fixes.append(f"I3 删豁免告警: {a.employee_id}/{a.scenario}")
                s.delete(a)
        for v in s.query(VerdictRow).all():
            ex = exc.get(v.employee_id, {}).get(v.intent)
            if ex and not (v.explanation or "").startswith("[已豁免"):
                v.explanation = f"[已豁免:{ex}] " + (v.explanation or "")
                fixes.append(f"I3 补豁免标注: {v.employee_id}/{v.intent}")

        # ---- I4: 求职研判窗口须含招聘域名(未豁免的) ----
        for v in s.query(VerdictRow).filter(VerdictRow.intent == "job_seeking").all():
            if v.intent in (exc.get(v.employee_id) or {}):
                continue
            sig, evs = _verdict_sig(s, v)
            if evs and sig.get("招聘求职", 0) == 0:
                v.intent = "baseline_deviation"
                v.risk_score = min(v.risk_score or 30, 45)
                fixes.append(f"I4 求职无据压回: {v.employee_id}@{str(v.window_start)[:10]}")

        # ---- I1+I2+I5: 告警对齐/关闭/恢复 ----
        ev_map = defaultdict(list)
        for v in s.query(VerdictRow).all():
            sig, evs = _verdict_sig(s, v)
            ev_map[(v.employee_id, v.intent)].append((v, sig, bool(evs)))
        for a in s.query(AlertRow).filter(AlertRow.scenario.in_(_SIG)).all():
            need = _SIG[a.scenario]
            cands = [t for t in ev_map.get((a.employee_id, a.scenario), [])
                     if any(t[1].get(k, 0) > 0 for k in need)
                     or (t[1].get("DOC写", 0) > 0 and a.scenario == "data_exfiltration")]
            if cands:
                best = max(cands, key=lambda t: (t[0].risk_score or 0))
                v = best[0]
                if a.verdict_id != v.id or a.risk_score != v.risk_score:
                    fixes.append(f"I1 对齐: {a.employee_id}/{a.scenario} vid {a.verdict_id}->{v.id} 分 {a.risk_score}->{v.risk_score}")
                    a.verdict_id, a.risk_score = v.id, v.risk_score
                    a.summary = v.explanation or a.summary
            elif a.status == "NEW":
                # I5: 查近7天真实行为
                sig = Counter()
                for e in s.query(EventRow).filter(
                        EventRow.employee_id == a.employee_id,
                        EventRow.occurred_at >= bj_now() - timedelta(days=7)).all():
                    if e.category == "WEB":
                        rc = dicts.risk_class(((e.raw or {}).get("domain") or "").lower())
                        if rc:
                            sig[rc] += (e.count or 1)
                hit = {k: v2 for k, v2 in sig.items() if k in need and v2 > 0}
                if hit:
                    txt = ",".join(f"{k}{v2}次" for k, v2 in hit.items())
                    if (a.summary or "").startswith("近7天"):
                        continue  # 已恢复过,不重复处理
                    a.summary = f"近7天持续访问风险域名({txt});原研判窗口事件已过保留期"
                    fixes.append(f"I5 恢复: {a.employee_id}/{a.scenario}({txt})")
                else:
                    a.status = "CLOSED"
                    fixes.append(f"I5 关闭无据: {a.employee_id}/{a.scenario}")

        # ---- 锚点档位吸附: policy/data/job 的NEW告警分数必须落在合法档位,
        # 档位外(历史AI自由分残留)向上吸附到最近合法档 ----
        for a in s.query(AlertRow).all():
            if a.status == "NEW" and a.scenario in _ANCHOR_TIERS and a.risk_score not in _ANCHOR_TIERS[a.scenario]:
                legal = sorted(x for x in _ANCHOR_TIERS[a.scenario] if x >= (a.risk_score or 0))
                if legal:
                    fixes.append(f"I6 档位吸附: {a.employee_id}/{a.scenario} {a.risk_score}->{legal[0]}")
                    a.risk_score = legal[0]

        s.commit()
        return {"checked": "all", "fixes": fixes}
    except Exception as e:
        s.rollback()
        return {"error": str(e)[:200]}
    finally:
        s.close()
