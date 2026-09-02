"""行为聚合告警(2026-08-20用户要求): 谁 在某时间段 大量 干了什么 → AI按5W汇总成告警。

首批场景: 大量删除文件 = 离职前清理前兆(结合文件名判断)。
规则(2026-09-02周键化): 本周任一单日非噪声删除≥15次且≥8个不同文件(突发,原日规则)
或全周≥40次/20个(持续慢删) → 触发;单日40+/全周100+ 升高危。告警按ISO周立行。
Qwen 按文件名列表写5W说明(谁/何时/通过什么/删了什么/属什么问题);
缓存/系统文件已排除(detector.is_noise_doc),只统计用户文档区的真实删除。
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import timedelta

from db import Session, EventRow, AlertRow, VerdictRow, bj_now, events_by_hashes, severity_of
import dicts
import detector

PROMPT = """你是企业行为安全分析师。输入: 某员工近几天(同一周内)删除的文件清单(IP-Guard,已排除系统/缓存文件)。
输出 JSON: {"summary": "按5W写一段: 谁(用输入的员工名)在何时(日期+时段)通过什么(本机删除)删了什么(数量+代表性文件名3-5个+类型归纳,如『试验报告类/合同类/个人文件类』),属于什么问题(大量删除=疑似离职前清理/数据销毁前兆,结合文件名特征判断更像工作清理还是敏感清理)"}
只输出JSON,summary一段话120字内。"""


def scan_mass_deletes() -> dict:
    s = Session()
    try:
        # 周键化(2026-09-02): 触发=本周任一单日≥15次/8个文件(突发,原日规则)或全周
        # ≥40次/20个(持续慢删);告警按ISO周立行,一周一格,同周晚到数据原地刷新计数。
        # 原2026-09-01按日立行(2天窗+日键): 持续清理者日行并排NEW,同人同场景最多
        # 10组并排(2026-09-01三页面审计),队列灌水且同事实重复计条。
        now = bj_now()
        wk_start = (now - timedelta(days=now.weekday())).date()  # 本周一
        iso = now.isocalendar()
        evs = s.query(EventRow).filter(EventRow.source == "ipguard",
                                        EventRow.category == "DOC",
                                        EventRow.action == "DELETE",
                                        EventRow.occurred_at >= now - timedelta(days=7)).all()
        by_emp = defaultdict(lambda: defaultdict(list))
        for e in evs:
            if e.occurred_at.date() < wk_start:
                continue  # 只统计本周: 跨周残留事件归上周行,避免周一换周时重复触发
            if detector.is_noise_doc(e):
                continue
            by_emp[e.employee_id][e.occurred_at.date()].append(e)
        created = updated = closed = merged = 0
        for emp, days in by_emp.items():
            week_n = sum(len(v) for v in days.values())
            files = sorted({(e.target_value or "").strip() for v in days.values()
                            for e in v if (e.target_value or "").strip()})
            week_nf = len(files)
            burst = max(days.values(), key=len) if days else []
            burst_nf = len({(e.target_value or "").strip() for e in burst if (e.target_value or "").strip()})
            key = f"{emp}|mass_delete|{iso[0]}-W{iso[1]:02d}"
            existing = s.query(AlertRow).filter_by(dedup_key=key).first()
            if not ((len(burst) >= 15 and burst_nf >= 8) or (week_n >= 40 and week_nf >= 20)):
                # 复算低于阈值 → 降噪关闭(噪声/白名单口径收紧后旧告警可能失真)
                if existing and existing.status == "NEW":
                    existing.status = "CLOSED"
                    existing.risk_score = 15
                    existing.severity = "LOW"
                    existing.summary = f"[复核更正: 按当前口径复算本周有效删除仅{week_n}次/{week_nf}个,低于聚合阈值,降噪关闭] " + (existing.summary or "")[:140]
                    closed += 1
                continue
            risk = 80 if len(burst) >= 40 or week_n >= 100 else 70
            sev = severity_of(risk)
            dist = "、".join(f"{d.strftime('%m%d')}×{len(v)}" for d, v in sorted(days.items()))
            last_ts = max(e.occurred_at for v in days.values() for e in v)
            if existing:
                if existing.status != "NEW":
                    continue  # 处置态不复活不重置(08-28口径)
                # 刷新: AI写的5W定性不整体重写,由可原地更新的[复核]尾标携带最新周计数
                _tag = f"[复核W{iso[1]:02d}:本周累计删除{week_n}次/{week_nf}个文件]"
                sm = re.sub(r"\s*\[复核[^\]]*\]$", "", existing.summary or "")
                if f"删除{week_n}次/{week_nf}个" not in sm:
                    sm = sm + " " + _tag
                existing.summary = sm
                existing.risk_score = risk
                existing.severity = sev
                existing.window_start = last_ts
                updated += 1
                print(f"[massops] {emp} 周行刷新 {week_n}次/{week_nf}文件 -> {risk}分", flush=True)
            else:
                hours = sorted({e.occurred_at.hour for v in days.values() for e in v})
                # 类型分布喂给AI: 构建/文档构成是"环境清理vs敏感清理"的关键判据(2026-09-01 27万次环境擦除案例)
                _ext = defaultdict(int)
                for v in days.values():
                    for e in v:
                        _m = re.search(r"\.([a-z0-9]{1,5})$", (e.target_value or "").lower())
                        _ext[_m.group(1) if _m else "无扩展"] += 1
                ext_txt = ", ".join(f"{k}×{c}" for k, c in sorted(_ext.items(), key=lambda x: -x[1])[:6])
                digest = (f"员工: {emp}\n本周({wk_start.strftime('%m-%d')}起,分日{dist}) 时段{hours[0]}-{hours[-1]}时\n"
                          f"共删除{week_n}次/{week_nf}个不同文件(类型分布: {ext_txt}):\n" + "\n".join(files[:40]))
                summary = ""
                try:
                    import llm_client
                    raw = llm_client.chat([{"role": "system", "content": PROMPT},
                                           {"role": "user", "content": digest[:6000]}],
                                          max_tokens=500, timeout=120)
                    txt = llm_client.strip_think(raw)
                    i = txt.find("{")
                    summary = (json.loads(txt[i:txt.rfind("}") + 1]) or {}).get("summary", "") if i >= 0 else ""
                except Exception:
                    pass
                if not summary:
                    _meh = ("__init__", "__pycache__", "RECORD", "WHEEL", "METADATA", "LICENSE", "INSTALLER", "entry_points")
                    _picks = [f for f in files if not f.startswith(_meh)][:4] or files[:4]
                    sample = "、".join(_picks)
                    summary = f"{emp}本周({wk_start.strftime('%m-%d')}起)删除{week_n}次/{week_nf}个文件(如{sample}),大量删除属疑似离职前清理,需核查"
                s.add(AlertRow(employee_id=emp, scenario="mass_delete",
                               severity=sev, risk_score=risk,
                               summary=summary, dedup_key=key,
                               window_start=last_ts, created_at=bj_now(), status="NEW"))
                created += 1
                print(f"[massops] {emp} 本周删除{week_n}次/{week_nf}文件 -> {risk}分", flush=True)
            # 日键时代的旧快照收编(无条件,镜像trend周键): 按日克隆行结构上已被周键
            # 取代,不收编则每人每天挂一条直到7天超龄,详情页并排数条同文案
            for old in s.query(AlertRow).filter(AlertRow.employee_id == emp,
                                                AlertRow.scenario == "mass_delete",
                                                AlertRow.status == "NEW").all():
                tail = (old.dedup_key or "").rsplit("|", 1)[-1]
                if "-W" in tail or (old.summary or "").startswith("["):
                    continue  # 周键行/带标记的复核行不动
                old.status = "CLOSED"
                old.summary = "[周期合并:同一持续大量删除已按周聚合,此日快照关闭] " + (old.summary or "")[:120]
                merged += 1
        from db import write_lock as _wl
        with _wl:  # 铁律: 写经统一写锁串行(2026-08-26补)
            s.commit()
        # ---- 外发量聚合(蚂蚁搬家检测,2026-08-21,周键化2026-09-02) ----
        created2 = scan_mass_exfil(s)
        return {"checked": len(by_emp), "created": created + created2,
                "updated": updated, "closed": closed, "merged": merged}
    finally:
        s.close()


def reconcile_late_evidence() -> dict:
    """晚到证据关联(2026-08-26朱亮案例的兜底): 深信服延迟批可能超过12分钟等待窗,
    对已产生的"目的地未记录"外发告警,用现已完整的浏览数据重新推断:
    全部上传都有白名单邻近 → 关闭(公司通道);发现非白名单邻近 → 回填[后到证据]。"""
    from datetime import datetime as _dt
    s = Session()
    try:
        _n = bj_now()
        closed = enriched = 0
        _wl = [w.lower() for w in dicts.get("risk_whitelist_domains") or []]
        for a in s.query(AlertRow).filter(
                AlertRow.scenario == "data_exfiltration", AlertRow.status == "NEW",
                AlertRow.summary.like("%目的地未记录%"),
                AlertRow.window_start >= _n - timedelta(hours=6)).all():
            v = s.get(VerdictRow, a.verdict_id) if a.verdict_id else None
            if not v:
                continue
            evs = events_by_hashes(s, v.event_hashes or [])
            sends = [e for e in evs if e.category == "DOC" and e.action in ("SEND", "UPLOAD")
                     and not dicts.dest_host(e.raw or {})]
            if not sends:
                continue
            webs = [(_ts(e2.occurred_at), ((e2.raw or {}).get("domain") or "").lower())
                    for e2 in s.query(EventRow).filter(
                        EventRow.employee_id == a.employee_id, EventRow.category == "WEB",
                        EventRow.occurred_at >= v.window_start - timedelta(minutes=30),
                        EventRow.occurred_at <= (v.window_end or v.window_start) + timedelta(minutes=30)).all()
                    if ((e2.raw or {}).get("domain") or "").lower()]
            webs.sort()

            def near(e):
                hit_wl, others = False, []
                for t, d in webs:
                    if abs((t - _ts(e.occurred_at)).total_seconds()) > 300:
                        continue
                    if any(d == x or d.endswith("." + x) for x in _wl):
                        hit_wl = True
                    elif d and not d.startswith(("ws.", "statistic.", "stat.", "log.", "tm.")) and d not in others:
                        others.append(d)
                return hit_wl, others

            results = [near(e) for e in sends]
            if results and all(h for h, _ in results):
                a.status = "CLOSED"
                a.risk_score = 15
                a.severity = "LOW"
                a.summary = "[白名单更正: 晚到的深信服浏览证据显示上传时刻同期为公司M365/Teams等白名单域名,实为公司通道传附件] " + (a.summary or "")[:160]
                closed += 1
            else:
                extra = sorted({d for _, o in results for d in o})[:2]
                if extra and "[后到证据" not in (a.summary or ""):
                    a.summary = (a.summary or "") + f" [后到证据:上传时刻同期浏览{'/'.join(extra)}]"
                    enriched += 1
        from db import write_lock as _wl
        with _wl:  # 铁律: 写经统一写锁串行(2026-08-26补)
            s.commit()
        return {"closed": closed, "enriched": enriched}
    finally:
        s.close()


def _ts(x):
    from datetime import datetime as _dt2
    return x if isinstance(x, _dt2) else _dt2.fromisoformat(str(x)[:19])


def scan_mass_exfil(s) -> int:
    """外发量聚合(2026-09-02周键化): 触发=本周任一日≥15次/50MB(突发,原日规则)
    或全周≥40次/150MB(持续蚂蚁搬家);告警按ISO周立行(只统计本周一起的事件),
    同周数据增长原地刷新;旧NEW日行无条件收编并周。
    原2026-08-26按日立行: 持续外发者同人同场景日行并排NEW最多10组,队列灌水
    且同一持续事实重复计条(2026-09-01三页面审计)。"""
    _wl = [w.lower() for w in dicts.get("risk_whitelist_domains") or []]
    now = bj_now()
    wk_start = (now - timedelta(days=now.weekday())).date()  # 本周一

    def _host(e):
        return dicts.dest_host(e.raw or {})  # 统一走共享工具: URL主机+剥端口(私有副本曾漏剥端口致ELN:5083匹配白名单失败)

    by_emp = defaultdict(lambda: defaultdict(list))
    _inferred = {}
    destless = []
    for e in s.query(EventRow).filter(EventRow.source == "ipguard",
                                       EventRow.occurred_at >= now - timedelta(days=7),
                                       EventRow.action.in_(("SEND", "UPLOAD"))).all():
        if e.occurred_at.date() < wk_start:
            continue  # 只统计本周: 跨周残留事件归上周行,避免周一换周时重复触发
        dest = _host(e)
        if dest and any(dest == w or dest.endswith("." + w) for w in _wl):
            continue
        if not dest:
            destless.append(e)
        by_emp[e.employee_id][e.occurred_at.date()].append(e)

    # 空目的地推断只查"有无目的地的外发"涉及员工的浏览(2026-09-02): 7天全量WEB约
    # 35万行,每10分钟整扫一遍只为极少数无目的地事件服务,改为按需取涉及的员工
    if destless:
        _emps = {e.employee_id for e in destless}
        webs = defaultdict(list)
        for w in s.query(EventRow).filter(EventRow.category == "WEB",
                                           EventRow.employee_id.in_(_emps),
                                           EventRow.occurred_at >= now - timedelta(days=7)).all():
            d = ((w.raw or {}).get("domain") or "").lower()
            if d:
                webs[w.employee_id].append((w.occurred_at, d))
        for k in webs:
            webs[k].sort()
        _drop = set()
        for e in destless:
            wl_hit, doms = False, []
            for t, d in webs.get(e.employee_id, ()):
                if abs((t - e.occurred_at).total_seconds()) > 180:
                    continue
                if any(d == x or d.endswith("." + x) for x in _wl):
                    wl_hit = True
                elif d not in doms:
                    doms.append(d)
            if wl_hit:
                _drop.add(e.id)
            elif doms:
                _inferred[(e.employee_id, e.id)] = doms[0][:36]
        if _drop:
            for emp in list(by_emp):
                for d in list(by_emp[emp]):
                    by_emp[emp][d] = [x for x in by_emp[emp][d] if x.id not in _drop]
                    if not by_emp[emp][d]:
                        del by_emp[emp][d]
            for emp in [k for k, v in by_emp.items() if not v]:
                del by_emp[emp]

    def _dest_show(e):
        d = dicts.dest_host(e.raw or {})
        if d:
            return d[:36]
        inf = _inferred.get((e.employee_id, e.id))
        if inf:
            return inf + "(同期浏览)"
        ch = (e.raw or {}).get("channel") or ""
        return (ch + "·未识别目的地") if ch and ch != "LOCAL" else "网络通道·未识别目的地"

    created = updated = closed = merged = 0
    iso = now.isocalendar()
    for emp, days in by_emp.items():
        week_n = sum(len(v) for v in days.values())
        week_mb = sum((e.size_bytes or 0) for v in days.values() for e in v) / 1048576
        burst = max(days.values(), key=len) if days else []
        burst_mb = max((sum((e.size_bytes or 0) for e in v) for v in days.values()), default=0) / 1048576
        key = f"{emp}|mass_exfil|{iso[0]}-W{iso[1]:02d}"
        existing = s.query(AlertRow).filter_by(dedup_key=key).first()
        if not (len(burst) >= 15 or burst_mb >= 50 or week_n >= 40 or week_mb >= 150):
            # 白名单口径变化后重算低于阈值 → 关闭残留告警(2026-08-26周逸飞案例:
            # filez.com加白当日,旧85分告警仍挂NEW)
            if existing and existing.status == "NEW" and "[白名单" not in (existing.summary or ""):
                existing.status = "CLOSED"
                existing.risk_score = 15
                existing.severity = "LOW"
                existing.summary = "[白名单更正: 按当前白名单口径重算本周低于聚合阈值(目的地实为公司通道/白名单域)] " + (existing.summary or "")[:140]
                closed += 1
            continue
        if existing and existing.status in ("FP", "CONFIRMED"):
            continue  # 用户已处置的不动
        peak_day = max(days, key=lambda d: len(days[d]))
        sample = "; ".join(f"『{(e.target_value or '未命名文件')[:48]}』→{_dest_show(e)}" for e in days[peak_day][:4])
        mode = "高频小批量·蚂蚁搬家模式" if week_n >= 15 else "少量大体量外发"
        big = max(((e.size_bytes or 0) for v in days.values() for e in v), default=0)
        big_txt = f",单文件最大{big / 1048576:.0f}MB" if big > 50 * 1048576 else ""
        dist = "、".join(f"{d.strftime('%m%d')}×{len(v)}" for d, v in sorted(days.items()))
        risk = 85 if (len(burst) >= 30 or burst_mb >= 100 or week_n >= 80 or week_mb >= 300) else 75
        sm = f"{emp}本周({wk_start.strftime('%m-%d')}起)向非白名单目的地累计外发{week_n}次、共{week_mb:.1f}MB{big_txt}({mode};日分布:{dist})。样例: {sample}"
        # 内容定性(2026-08-26用户要求: 外发不能只看次数大小,要结合文件名推断):
        # 新建时由本地AI对文件清单做语义定性,敏感内容提分并写入说明;刷新时原摘要
        # 会被整体重写,须把[内容定性:]标签携带到新摘要,否则定性证据丢失(2026-09-02)
        _carry = ""
        if existing:
            i0 = (existing.summary or "").find("[内容定性:")
            if i0 >= 0:
                _carry = " " + (existing.summary or "")[i0:].split("]")[0] + "]"
        if not existing:
            try:
                import llm_client
                _files = list({(e.target_value or "") for v in days.values() for e in v if (e.target_value or "")})[:20]
                _p2 = ("对以下员工外发文件名清单做内容定性,输出JSON {sensitivity: high|mid|none, desc: 一句话(引用代表性文件名)}。"
                       "high=实验/临床/项目数据/合同财务/数据库;mid=含项目编号的办公文档;none=缓存/私人生活文件。只输出JSON。文件: "
                       + "; ".join(_files))
                _raw = llm_client.chat([{"role": "system", "content": _p2}], max_tokens=200, timeout=90)
                _txt = llm_client.strip_think(_raw)
                _j2 = json.loads(_txt[_txt.find("{"):_txt.rfind("}") + 1])
                if _j2.get("sensitivity") == "high":
                    risk = max(risk, 85)
                    sm += f" [内容定性:{_j2.get('desc') or '敏感实验/项目数据'}]"
                elif _j2.get("sensitivity") == "mid":
                    sm += f" [内容定性:{_j2.get('desc') or '项目相关文档'}]"
            except Exception:
                pass
        elif _carry:
            sm += _carry
        sev = severity_of(risk)
        last_ts = max(e.occurred_at for v in days.values() for e in v)
        if existing:
            existing.summary = sm
            existing.risk_score = risk
            existing.severity = sev
            existing.window_start = last_ts
            updated += 1
        else:
            s.add(AlertRow(employee_id=emp, scenario="mass_exfil",
                           severity=sev, risk_score=risk, summary=sm,
                           dedup_key=key, window_start=last_ts, created_at=bj_now(), status="NEW"))
            created += 1
        print(f"[massops-exfil] {emp} 本周外发{week_n}次/{week_mb:.0f}MB -> {risk}分" + ("(刷新)" if existing else ""), flush=True)
        # 日键时代的旧快照收编(无条件,镜像trend周键)
        for old in s.query(AlertRow).filter(AlertRow.employee_id == emp,
                                            AlertRow.scenario == "mass_exfil",
                                            AlertRow.status == "NEW").all():
            tail = (old.dedup_key or "").rsplit("|", 1)[-1]
            if "-W" in tail or (old.summary or "").startswith("["):
                continue  # 周键行/带标记的复核行不动
            old.status = "CLOSED"
            old.summary = "[周期合并:同一持续外发已按周聚合,此日快照关闭] " + (old.summary or "")[:120]
            merged += 1
    from db import write_lock as _wl
    with _wl:  # 铁律: 写经统一写锁串行(2026-08-26补)
        s.commit()
    return created
