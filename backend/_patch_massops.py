# -*- coding: utf-8 -*-
import io

p = "backend/massops.py"
s = io.open(p, encoding="utf-8").read()

# 整函数替换(77-163行区间,锚定函数头尾)
start = s.find("def scan_mass_exfil(s) -> int:")
end = s.find("    s.commit()\n    return created", start) + len("    s.commit()\n    return created")
assert start > 0 and end > start

new_fn = '''def scan_mass_exfil(s) -> int:
    """外发量聚合: 单日历日非白名单SEND/UPLOAD≥15次 或 总量≥50MB → 告警。
    2026-08-26: 按日历日分组(原滚动24h跨日混键,周逸飞案例);同日数据增长时
    刷新已有告警的摘要/分数(原跳过导致摘要停留在首次扫描快照——柏芳3→8次)。"""
    _wl = [w.lower() for w in dicts.get("risk_whitelist_domains") or []]
    webs = defaultdict(list)
    for w in s.query(EventRow).filter(EventRow.category == "WEB",
                                       EventRow.occurred_at >= bj_now() - timedelta(days=1)).all():
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
        d = ((e.raw or {}).get("dest_path") or "").strip().lower()
        if d.startswith(("http:", "https:")):
            _p = d.split("/")
            d = _p[2] if len(_p) > 2 else d
        else:
            d = d.split("/")[0]
        return d

    by_emp_day = defaultdict(list)
    _inferred = {}
    for e in s.query(EventRow).filter(EventRow.source == "ipguard",
                                       EventRow.occurred_at >= bj_now() - timedelta(days=1),
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
        d = _host(e)
        if d:
            return d[:36]
        inf = _inferred.get((e.employee_id, e.id))
        if inf:
            return inf + "(同期浏览)"
        ch = (e.raw or {}).get("channel") or ""
        return (ch + "·未识别目的地") if ch and ch != "LOCAL" else "网络通道·未识别目的地"

    created = updated = 0
    for (emp, day_d), lst in by_emp_day.items():
        total_mb = sum((e.size_bytes or 0) for e in lst) / 1048576
        if len(lst) < 15 and total_mb < 50:
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
    s.commit()
    return created'''

s = s[:start] + new_fn + s[end:]
io.open(p, "w", encoding="utf-8", newline="\n").write(s)
print("scan_mass_exfil 整函数替换完成")
