"""系统自检自愈(每小时维护调用)。

固化2026-08-19/20连续审计中用户发现的所有问题类型为不变量,自动巡检+修复。
不变量清单(每条都源于真实案例):
  I1 告警场景必须与研判窗口证据一致(万亮: job告警窗口全是AI域名)
  I2 告警分=研判分, verdict_id不悬空(告警挂在被删/改意图的研判上)
  I3 豁免场景无告警行, 豁免研判带[已豁免]前缀(展佳: HR豁免后研判高分可见)
  I4 求职研判窗口必须含招聘域名(纯AI窗口被当日累计裹挟)
  I5 无窗口证据但近7天有真实行为的告警→改写说明保留; 完全无据→关闭
  I7 verdict_id必须指向本人研判: 全量重判会删旧verdicts重建,行号id被复用,
     老告警的verdict_id会指到别人的研判(2026-08-24审计99条错位)——错位/悬空
     时按(同人+同意图+窗口±3h)重连,找不到则置NULL让告警独立存在
复核标记保护: 带[N+1复核/[次日复核/[研判已降至 前缀的告警,分数是复核结论
     (N+1降分只写告警不改研判),I1/I6对齐会把它改回研判分造成拉锯——一律跳过。
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import timedelta

import dicts
from db import AlertRow, EventRow, ExceptionRow, Session, VerdictRow, bj_now, severity_of

_DOC_W = ("COPY", "MOVE", "DELETE", "UPLOAD", "SEND", "PRINT", "BURN")
_SIG = {"policy_violation": ("网盘/云盘", "个人邮箱"),
        "data_exfiltration": ("微信文件助手", "网盘/云盘", "个人邮箱")}
_ANCHOR_TIERS = {"policy_violation": {75, 80, 85, 90},
                 "data_exfiltration": {75, 80, 85, 90, 95},
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


def _reviewed(a):
    """带复核标记的告警: 分数由N+1复核结论决定(降分只写告警),对齐类不变量跳过。"""
    sm = a.summary or ""
    return (sm.startswith(("[次日复核", "[N+1复核", "[重判后复核"))
            or "[研判已降至" in sm or "[白名单" in sm or "[巡检" in sm)


def selfcheck() -> dict:
    """带重试的外壳(2026-08-21): 长事务撞锁/autoflush失败时回滚重试,
    单轮部分修复不丢失——已提交语义由幂等检查保证(下轮自然收敛)。"""
    import time as _t
    last_err = None
    for _i in range(3):
        try:
            return _selfcheck_once()
        except Exception as ex:
            last_err = str(ex)[:200]
            _t.sleep(3)
    return {"error": f"重试3次仍失败: {last_err}"}


def _selfcheck_once() -> dict:
    from db import write_lock as _wl
    with _wl:  # 2026-08-24: 全程持统一写锁——与入库flush/画像重建/改名清洗串行,
    # 否则中途UPDATE撞上它们持锁时在busy_timeout上等满30s报database is locked
        return _selfcheck_body()


def _selfcheck_body() -> dict:
    fixes = []
    s = Session()
    try:
        # 豁免表(2026-08-24: 只认未到期豁免——原全量加载,到期豁免仍会删告警)
        from datetime import datetime as _dt
        _now_u = _dt.utcnow()
        exc = defaultdict(dict)
        for x in s.query(ExceptionRow).all():
            if x.expires_at and x.expires_at <= _now_u:
                continue  # 已到期:豁免失效,告警恢复正常
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
                # ③级联到挂靠告警(2026-08-28 id330): 告警是按旧intent(job_seeking)
                # 立的案,压回后不跟着处理就变成scenario/分数错位悬挂。无招聘证据
                # =立案件不成立 → 与I5"完全无据→关闭"同口径处理;已处置/已复核不动。
                for _a in s.query(AlertRow).filter(AlertRow.verdict_id == v.id).all():
                    if _a.status in ("FP", "CONFIRMED", "CLOSED") or _reviewed(_a):
                        continue
                    _a.status = "CLOSED"
                    _a.risk_score = min(_a.risk_score or 0, v.risk_score or 0)
                    _a.severity = severity_of(_a.risk_score or 0)
                    _a.summary = "[I4压回:窗口无招聘域名证据,自动关闭] " + (_a.summary or "")
                    fixes.append(f"I4 告警级联关闭: alert#{_a.id} {v.employee_id}/{_a.scenario}")

        # ---- I7: verdict_id链接完整性(先于I1,保证后续对齐建立在正确链接上) ----
        for a in s.query(AlertRow).filter(AlertRow.verdict_id.isnot(None)).all():
            v = s.get(VerdictRow, a.verdict_id)
            # ③intent必须一致(2026-08-28 id330案例): I4会把verdict的intent原地
            # 压回(如job_seeking→baseline_deviation),只查employee放过了这种
            # "job_seeking告警挂着baseline_deviation研判"的错位悬挂
            if v is not None and v.employee_id == a.employee_id and v.intent == a.scenario:
                continue  # 链接正确
            cand = None
            if a.window_start is not None:
                vs = s.query(VerdictRow).filter(
                    VerdictRow.employee_id == a.employee_id,
                    VerdictRow.intent == a.scenario,
                    VerdictRow.window_start >= a.window_start - timedelta(hours=3),
                    VerdictRow.window_start <= a.window_start + timedelta(hours=3)
                ).all()
                cand = min(vs, key=lambda x: abs((x.window_start - a.window_start).total_seconds())) if vs else None
            if cand is not None:
                fixes.append(f"I7 重连: {a.employee_id}/{a.scenario} vid {a.verdict_id}->{cand.id}")
                a.verdict_id = cand.id
                if not _reviewed(a):
                    a.risk_score = cand.risk_score or a.risk_score
            else:
                fixes.append(f"I7 断开错链: {a.employee_id}/{a.scenario} vid {a.verdict_id}(指向他人或已删)")
                a.verdict_id = None

        # ---- I1+I2+I5: 告警对齐/关闭/恢复 ----
        ev_map = defaultdict(list)
        for v in s.query(VerdictRow).all():
            sig, evs = _verdict_sig(s, v)
            ev_map[(v.employee_id, v.intent)].append((v, sig, bool(evs)))
        for a in s.query(AlertRow).filter(AlertRow.scenario.in_(_SIG)).all():
            # CONFIRMED也跳过(2026-08-26): 用户已知晓的告警,其分数/说明是处置时
            # 认可过的结论——重判后再对齐改写等于替用户翻案(massops同场景早已跳过,
            # 两模块口径统一);复犯会生成新研判并经告警刷新逻辑另行提醒
            if a.status in ("FP", "CONFIRMED") or _reviewed(a):
                continue  # 用户处置/复核结论优先,不对齐(防与N+1降分拉锯)
            need = _SIG[a.scenario]
            cands = [t for t in ev_map.get((a.employee_id, a.scenario), [])
                     if any(t[1].get(k, 0) > 0 for k in need)
                     or (t[1].get("DOC写", 0) > 0 and a.scenario == "data_exfiltration")]
            if cands:
                # 对齐目标=最新窗口的研判(2026-08-24田纪元案例: 08-22的90分研判
                # 被max选中粘住,当日最新研判80分反而不对齐——与口径"告警分=最新
                # 告警级研判分"矛盾);同窗口并列时才取高分
                best = max(cands, key=lambda t: (t[0].window_start, t[0].risk_score or 0))
                v = best[0]
                if a.verdict_id != v.id or a.risk_score != v.risk_score:
                    fixes.append(f"I1 对齐: {a.employee_id}/{a.scenario} vid {a.verdict_id}->{v.id} 分 {a.risk_score}->{v.risk_score}")
                    a.verdict_id, a.risk_score = v.id, v.risk_score
                    a.severity = severity_of(v.risk_score or 0)
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
                    # 幂等(2026-08-26修复): 实际写入的前缀是"[重判后复核]",旧检查
                    # startswith("近7天")永不命中→同批告警每10分钟被重写一遍
                    if (a.summary or "").startswith(("[重判后复核", "近7天")):
                        continue  # 已恢复过,不重复处理
                    # 优先重建事实说明: 事件90天保留,窗口数据仍在——按告警窗口
                    # 前后取该员工风险行为,给出5W式模板(2026-08-21用户反馈模板句
                    # "已过保留期"误导且信息量低)
                    fact = ""
                    if a.window_start:
                        w0 = a.window_start - timedelta(minutes=30)
                        w1 = a.window_start + timedelta(minutes=120)
                        wcnt = Counter()
                        wdoc = []
                        for e in s.query(EventRow).filter(
                                EventRow.employee_id == a.employee_id,
                                EventRow.occurred_at >= w0, EventRow.occurred_at < w1).all():
                            if e.category == "WEB":
                                d = ((e.raw or {}).get("domain") or "").lower()
                                rc = dicts.risk_class(d)
                                if rc:
                                    wcnt[f"{rc}:{d}"] += (e.count or 1)
                            elif e.category == "DOC" and e.action in ("SEND", "UPLOAD", "PRINT"):
                                dest = ((e.raw or {}).get("dest_path") or "").split("/")[0][:30]
                                wdoc.append(f"{(e.target_value or '')[:28]}→{dest}")
                        if wcnt:
                            fact = "、".join(f"{k}×{v2}" for k, v2 in wcnt.most_common(3))
                        elif wdoc:
                            fact = "外发:" + ";".join(wdoc[:2])
                    if fact:
                        a.summary = (f"[重判后复核] {a.employee_id}在{str(a.window_start)[:10]} "
                                     f"窗口行为:{fact};近7天持续存在同类访问("
                                     + ",".join(f"{k}{v2}次" for k, v2 in hit.items()) + ")")
                    else:
                        a.summary = f"[重判后复核] 近7天持续访问风险域名({','.join(f'{k}{v2}次' for k, v2 in hit.items())});原窗口无留存明细"
                    fixes.append(f"I5 恢复: {a.employee_id}/{a.scenario}({','.join(f'{k}{v2}' for k, v2 in hit.items())})")
                else:
                    a.status = "CLOSED"
                    fixes.append(f"I5 关闭无据: {a.employee_id}/{a.scenario}")

        # ---- 锚点档位吸附: 先吸研判(源头)再吸告警——只吸告警会和I1对齐
        # 无限震荡(2026-08-20实测: 刘倩雯75->70(I1)->75(I6)每轮拉锯) ----
        for v in s.query(VerdictRow).filter(VerdictRow.intent.in_(_ANCHOR_TIERS)).all():
            tiers = _ANCHOR_TIERS[v.intent]
            if (v.risk_score or 0) >= 50 and v.risk_score not in tiers:
                legal = sorted(x for x in tiers if x >= (v.risk_score or 0))
                if legal:
                    fixes.append(f"I6 研判档位吸附: {v.employee_id}/{v.intent} {v.risk_score}->{legal[0]}")
                    v.risk_score = legal[0]
        for a in s.query(AlertRow).all():
            # 2026-08-26: 只吸≥50——复犯刷新会把告警分更新为最新研判分(可能30/45),
            # 吸附把它硬拉回75+造成"告警80/研判45"错位(当日审计8条);<50非告警级不吸
            if a.status == "NEW" and not _reviewed(a) and a.scenario in _ANCHOR_TIERS                     and 50 <= (a.risk_score or 0) and a.risk_score not in _ANCHOR_TIERS[a.scenario]:
                legal = sorted(x for x in _ANCHOR_TIERS[a.scenario] if x >= (a.risk_score or 0))
                if legal:
                    fixes.append(f"I6 档位吸附: {a.employee_id}/{a.scenario} {a.risk_score}->{legal[0]}")
                    a.risk_score = legal[0]
                    a.severity = severity_of(legal[0])

        # ---- I8: 僵尸告警关闭(2026-08-28) ----
        # 全量重判删verdicts重建,只重触发活跃窗口;其余告警的verdict_id悬空
        # (08-28实测333/419)或窗口超7天不复现——NEW态永久挂着误导运营
        # (300条zombie里47条超出重判范围、206条重判前就已悬空)。处置态与
        # 复核标记一律不动,只清NEW僵尸:
        #  a) verdict_id悬空(verdict已删且未重触发) → 关
        #  b) 窗口起点超7天未复现(含规则直出无verdict的告警) → 关
        _stale_cut = bj_now() - timedelta(days=7)
        for a in s.query(AlertRow).filter(AlertRow.status == "NEW").all():
            if _reviewed(a):
                continue
            _dead = bool(a.verdict_id) and s.get(VerdictRow, a.verdict_id) is None
            _old = bool(a.window_start) and a.window_start < _stale_cut
            if not (_dead or _old):
                continue
            _why = "研判已失效(重判未复现)" if _dead else "窗口超7天未复现"
            a.status = "CLOSED"
            a.summary = f"[I8自动关闭:{_why}] " + (a.summary or "")[:500]
            fixes.append(f"I8 关僵尸: alert#{a.id} {a.employee_id}/{a.scenario}({_why[:4]})")

        s.commit()
        return {"checked": "all", "fixes": fixes}
    except Exception as e:
        s.rollback()
        return {"error": str(e)[:200]}
    finally:
        s.close()
