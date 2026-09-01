"""行为聚合告警(2026-08-20用户要求): 谁 在某时间段 大量 干了什么 → AI按5W汇总成告警。

首批场景: 大量删除文件 = 离职前清理前兆(结合文件名判断)。
规则: 单日非噪声删除 ≥15 个且 ≥8 个不同文件 → 触发;40+ 升高危。
Qwen 按文件名列表写5W说明(谁/何时/通过什么/删了什么/属什么问题);
缓存/系统文件已排除(detector.is_noise_doc),只统计用户文档区的真实删除。
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import timedelta

from db import Session, EventRow, AlertRow, VerdictRow, bj_now, events_by_hashes
import dicts
import detector

PROMPT = """你是企业行为安全分析师。输入: 某员工一天内删除的文件清单(IP-Guard,已排除系统/缓存文件)。
输出 JSON: {"summary": "按5W写一段: 谁(用输入的员工名)在何时(日期+时段)通过什么(本机删除)删了什么(数量+代表性文件名3-5个+类型归纳,如『试验报告类/合同类/个人文件类』),属于什么问题(大量删除=疑似离职前清理/数据销毁前兆,结合文件名特征判断更像工作清理还是敏感清理)"}
只输出JSON,summary一段话120字内。"""


def scan_mass_deletes() -> dict:
    s = Session()
    try:
        # 2026-09-01: 窗口1天→2天并按日历日分组(原滚动24h整桶按员工: 跨天事件混进同一天键,
        # 且超过1天的行永远扫不到,计数停在首扫快照——存量25条中21条过期)
        since = bj_now() - timedelta(days=2)
        evs = s.query(EventRow).filter(EventRow.source == "ipguard",
                                        EventRow.category == "DOC",
                                        EventRow.action == "DELETE",
                                        EventRow.occurred_at >= since).all()
        by_emp_day = defaultdict(list)
        for e in evs:
            if detector.is_noise_doc(e):
                continue
            by_emp_day[(e.employee_id, e.occurred_at.date())].append(e)
        created = updated = closed = skipped = 0
        for (emp, day_d), lst in by_emp_day.items():
            files = sorted({(e.target_value or "").strip() for e in lst if (e.target_value or "").strip()})
            n, nf = len(lst), len(files)
            day = day_d.strftime("%Y-%m-%d")
            key = f"{emp}|mass_delete|{day}"
            existing = s.query(AlertRow).filter_by(dedup_key=key).first()
            if n < 15 or nf < 8:
                # 复算低于阈值 → 降噪关闭(镜像scan_mass_exfil白名单更正分支;噪声口径收紧后旧告警可能失真)
                if existing and existing.status == "NEW":
                    existing.status = "CLOSED"
                    existing.risk_score = 15
                    existing.severity = "LOW"
                    existing.summary = f"[复核更正: 按当前噪声口径复算当日有效删除仅{n}次/{nf}个,低于聚合阈值,降噪关闭] " + (existing.summary or "")[:140]
                    closed += 1
                continue
            risk = 80 if n >= 40 else 70
            sev = "CRITICAL" if risk >= 76 else "HIGH"
            if existing:
                if existing.status != "NEW":
                    skipped += 1
                    continue
                # 刷新(2026-09-01,镜像scan_mass_exfil): 同日数据晚到增长时对齐计数/档位;
                # AI写的5W定性不整体重写,由可原地更新的[复核]尾标携带最新计数
                _tag = f"[复核{day[5:].replace('-', '')}:当日累计删除{n}次/{nf}个文件]"
                sm = re.sub(r"\s*\[复核[^\]]*\]$", "", existing.summary or "")
                if f"删除{n}次/{nf}个" not in sm:
                    sm = sm + " " + _tag
                existing.summary = sm
                existing.risk_score = risk
                existing.severity = sev
                existing.window_start = max(e.occurred_at for e in lst)
                updated += 1
                print(f"[massops] {emp} {day} 刷新为{n}次/{nf}文件 -> {risk}分", flush=True)
                continue
            hours = sorted({e.occurred_at.hour for e in lst})
            # 类型分布喂给AI: 构建/文档构成是"环境清理vs敏感清理"的关键判据(2026-09-01 27万次环境擦除案例)
            _ext = defaultdict(int)
            for e in lst:
                _m = re.search(r"\.([a-z0-9]{1,5})$", (e.target_value or "").lower())
                _ext[_m.group(1) if _m else "无扩展"] += 1
            ext_txt = ", ".join(f"{k}×{c}" for k, c in sorted(_ext.items(), key=lambda x: -x[1])[:6])
            digest = f"员工: {emp}\n日期: {day} 时段{hours[0]}-{hours[-1]}时\n共删除{n}次/{nf}个不同文件(类型分布: {ext_txt}):\n" + "\n".join(files[:40])
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
                summary = f"{emp}在{day}通过本机删除{n}次/{nf}个文件(如{sample}),大量删除属疑似离职前清理,需核查"
            s.add(AlertRow(employee_id=emp, scenario="mass_delete",
                           severity=sev, risk_score=risk,
                           summary=summary, dedup_key=key,
                           window_start=max(e.occurred_at for e in lst), created_at=bj_now(), status="NEW"))
            created += 1
            print(f"[massops] {emp} {day} 删除{n}次/{nf}文件 -> {risk}分", flush=True)
        from db import write_lock as _wl
        with _wl:  # 铁律: 写经统一写锁串行(2026-08-26补)
            s.commit()
        # ---- 外发量聚合(蚂蚁搬家检测,2026-08-21): 单日≥15次或≥50MB ----
        created2 = scan_mass_exfil(s)
        return {"checked": len(by_emp_day), "created": created + created2,
                "updated": updated, "closed": closed, "skipped": skipped}
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
    """外发量聚合: 单日历日非白名单SEND/UPLOAD≥15次 或 总量≥50MB → 告警。
    2026-08-26: 按日历日分组(原滚动24h跨日混键,周逸飞案例);同日数据增长时
    刷新已有告警的摘要/分数(原跳过导致摘要停留在首次扫描快照——柏芳3→8次)。"""
    _wl = [w.lower() for w in dicts.get("risk_whitelist_domains") or []]
    webs = defaultdict(list)
    for w in s.query(EventRow).filter(EventRow.category == "WEB",
                                       EventRow.occurred_at >= bj_now() - timedelta(days=2)).all():
        d = ((w.raw or {}).get("domain") or "").lower()
        if d:
            webs[w.employee_id].append((w.occurred_at, d))
    for k in webs:
        webs[k].sort()

    def _nearby(emp, ts):
        wl_hit, doms = False, []
        for t, d in webs.get(emp, ()):
            if abs((t - ts).total_seconds()) > 180:
                continue
            if any(d == x or d.endswith("." + x) for x in _wl):
                wl_hit = True
            elif d not in doms:
                doms.append(d)
        return wl_hit, doms

    def _host(e):
        return dicts.dest_host(e.raw or {})  # 统一走共享工具: URL主机+剥端口(私有副本曾漏剥端口致ELN:5083匹配白名单失败)

    by_emp_day = defaultdict(list)
    _inferred = {}
    for e in s.query(EventRow).filter(EventRow.source == "ipguard",
                                       EventRow.occurred_at >= bj_now() - timedelta(days=2),
                                       EventRow.action.in_(("SEND", "UPLOAD"))).all():
        dest = _host(e)
        if dest and any(dest == w or dest.endswith("." + w) for w in _wl):
            continue
        if not dest:
            wl_hit, doms = _nearby(e.employee_id, e.occurred_at)
            if wl_hit:
                continue
            if doms:
                _inferred[(e.employee_id, e.id)] = doms[0][:36]
        by_emp_day[(e.employee_id, e.occurred_at.date())].append(e)

    def _dest_show(e):
        d = dicts.dest_host(e.raw or {})
        if d:
            return d[:36]
        inf = _inferred.get((e.employee_id, e.id))
        if inf:
            return inf + "(同期浏览)"
        ch = (e.raw or {}).get("channel") or ""
        return (ch + "·未识别目的地") if ch and ch != "LOCAL" else "网络通道·未识别目的地"

    created = updated = closed = 0
    for (emp, day_d), lst in by_emp_day.items():
        total_mb = sum((e.size_bytes or 0) for e in lst) / 1048576
        if len(lst) < 15 and total_mb < 50:
            # 白名单口径变化后重算低于阈值 → 关闭残留告警(2026-08-26周逸飞案例:
            # filez.com加白当日,旧85分告警仍挂NEW)
            _stale = s.query(AlertRow).filter_by(dedup_key=f"{emp}|mass_exfil|{day_d.strftime('%Y-%m-%d')}").first()
            if _stale and _stale.status == "NEW" and "[白名单" not in (_stale.summary or ""):
                _stale.status = "CLOSED"
                _stale.risk_score = 15
                _stale.severity = "LOW"
                _stale.summary = "[白名单更正: 按当前白名单口径重算低于聚合阈值(目的地实为公司通道/白名单域)] " + (_stale.summary or "")[:140]
                closed += 1
            continue
        day = day_d.strftime("%Y-%m-%d")
        key = f"{emp}|mass_exfil|{day}"
        existing = s.query(AlertRow).filter_by(dedup_key=key).first()
        if existing and existing.status in ("FP", "CONFIRMED"):
            continue  # 用户已处置的不动
        sample = "; ".join(f"『{(e.target_value or '未命名文件')[:48]}』→{_dest_show(e)}" for e in lst[:4])
        mode = "高频小批量·蚂蚁搬家模式" if len(lst) >= 15 else "少量大体量外发"
        big = max(((e.size_bytes or 0) for e in lst), default=0)
        big_txt = f",单文件最大{big / 1048576:.0f}MB" if big > 50 * 1048576 else ""
        risk = 85 if len(lst) >= 30 or total_mb >= 100 else 75
        sm = f"{emp}在{day}向非白名单目的地累计外发{len(lst)}次、共{total_mb:.1f}MB{big_txt}({mode})。样例: {sample}"
        # 内容定性(2026-08-26用户要求: 外发不能只看次数大小,要结合文件名推断):
        # 新建时由本地AI对文件清单做语义定性,敏感内容提分并写入说明;刷新时保留
        if not existing:
            try:
                import llm_client
                _files = list({(e.target_value or "") for e in lst if (e.target_value or "")})[:20]
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
        sev = "CRITICAL" if risk >= 76 else "HIGH"
        if existing:
            existing.summary = sm
            existing.risk_score = risk
            existing.severity = sev
            existing.window_start = lst[-1].occurred_at
            updated += 1
        else:
            s.add(AlertRow(employee_id=emp, scenario="mass_exfil",
                           severity=sev, risk_score=risk, summary=sm,
                           dedup_key=key, window_start=lst[-1].occurred_at, created_at=bj_now(), status="NEW"))
            created += 1
        print(f"[massops-exfil] {emp} {day} 外发{len(lst)}次/{total_mb:.0f}MB -> {risk}分" + ("(刷新)" if existing else ""), flush=True)
    from db import write_lock as _wl
    with _wl:  # 铁律: 写经统一写锁串行(2026-08-26补)
        s.commit()
    return created
