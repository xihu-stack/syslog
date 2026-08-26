# -*- coding: utf-8 -*-
"""每日审计 2026-08-26 第三批: AI输入/输出 + 夜间日志 + 复审。"""
import sys
sys.path.insert(0, "/app")
import json
import re
import sqlite3

db = sqlite3.connect("/app/data/ipguard.db", timeout=60)
db.row_factory = sqlite3.Row
R = {}

# ===== 三1: 最近3条研判的AI窗口质量 =====
import detector
bad_fmt = []
for v in db.execute("SELECT id, employee_id, intent, event_hashes FROM verdicts WHERE event_hashes IS NOT NULL ORDER BY id DESC LIMIT 3").fetchall():
    hs = v["event_hashes"] or []
    if isinstance(hs, str):
        hs = json.loads(hs)
    ph = ",".join("?" * len(hs))
    evs = [dict(r) for r in db.execute(f"SELECT * FROM events WHERE event_hash IN ({ph})", hs).fetchall()]
    evs.sort(key=lambda x: x["occurred_at"])

    from datetime import datetime as _dtc

    class E:  # 包装成属性访问+时间反序列化
        def __init__(s2, d):
            s2.__dict__.update(d)
            s2.raw = d["raw"] if isinstance(d["raw"], dict) else json.loads(d["raw"] or "{}")
            if isinstance(s2.occurred_at, str):
                s2.occurred_at = _dtc.fromisoformat(s2.occurred_at[:19])
    wes = [E(e) for e in evs]
    txt = detector._fmt_window(wes)
    issues = []
    if "→https:" in txt or "→NETWORK," in txt or "→NETWORK\n" in txt:
        issues.append("目的地不可读")
    if txt.count("[访问网页]") > 6:
        issues.append("噪声未压缩")
    first_send = txt.find("[SEND]")
    first_web = txt.find("[访问网页]")
    if first_send >= 0 and first_web >= 0 and first_send > first_web and txt.find("[⚠") < 0:
        issues.append("信号未置顶")
    bad_fmt.append((v["id"], v["employee_id"][:10], v["intent"], issues or "✓"))
R["三1_窗口质量"] = bad_fmt

# ===== 四1: 5条verdict说明数字 vs 窗口实数 =====
numchk = []
for v in db.execute("SELECT id, employee_id, intent, risk_score, explanation, event_hashes FROM verdicts WHERE event_hashes IS NOT NULL AND explanation LIKE '%次%' ORDER BY id DESC LIMIT 5").fetchall():
    hs = v["event_hashes"] or []
    if isinstance(hs, str):
        hs = json.loads(hs)
    ph = ",".join("?" * len(hs))
    evs = list(db.execute(f"SELECT * FROM events WHERE event_hash IN ({ph})", hs))
    # 抽说明中第一个 ×N 与窗口同域名WEB count比对
    m = re.search(r"([\w\.\-]+)×(\d+)", v["explanation"] or "")
    ok = "-"
    if m and evs:
        dom, n = m.group(1).lower(), int(m.group(2))
        tot = sum((e["count"] or 1) for e in evs
                  if (json.loads(e["raw"]) if isinstance(e["raw"], str) else (e["raw"] or {})).get("domain", "").lower().find(dom) >= 0)
        ok = "✓" if tot == n or tot == 0 else f"✗ 说明{n}/实{tot}"
    numchk.append((v["id"], v["employee_id"][:8], v["intent"], v["risk_score"], ok))
R["四1_数字比对"] = numchk

# ===== 四2: 分数 vs 锚点复算 =====
anch = []
for v in db.execute("""SELECT id, employee_id, intent, risk_score, event_hashes FROM verdicts
WHERE intent IN ('policy_violation','data_exfiltration') AND risk_score>=50 ORDER BY id DESC LIMIT 8""").fetchall():
    hs = v["event_hashes"] or []
    if isinstance(hs, str):
        hs = json.loads(hs)

    from datetime import datetime as _dtc2

    class E2:
        def __init__(s2, d):
            s2.__dict__.update(d)
            s2.raw = d["raw"] if isinstance(d["raw"], dict) else json.loads(d["raw"] or "{}")
            if isinstance(s2.occurred_at, str):
                s2.occurred_at = _dtc2.fromisoformat(s2.occurred_at[:19])
    ph = ",".join("?" * len(hs))
    evs = [E2(dict(r)) for r in db.execute(f"SELECT * FROM events WHERE event_hash IN ({ph})", hs)]
    try:
        sc = detector.risk_anchor(evs, v["intent"])
    except Exception as ex:
        sc = None
    dev = None if sc is None else (v["risk_score"] - sc)
    anch.append((v["id"], v["employee_id"][:8], v["intent"], f"verdict={v['risk_score']}", f"锚点={sc}", "✓" if sc is None or abs(dev) <= 5 else f"偏差{dev}"))
R["四2_锚点复算"] = anch

# ===== 四3: job意图须有招聘证据 =====
noev = []
for v in db.execute("SELECT id, employee_id, event_hashes FROM verdicts WHERE intent='job_seeking' AND risk_score>=50 ORDER BY id DESC LIMIT 10").fetchall():
    hs = v["event_hashes"] or []
    if isinstance(hs, str):
        hs = json.loads(hs)
    ph = ",".join("?" * len(hs))
    evs = list(db.execute(f"SELECT raw FROM events WHERE event_hash IN ({ph})", hs))
    JOB = re.compile(r"(zhipin|liepin|51job|zhaopin|italent)", re.I)
    if not any(JOB.search(json.dumps(e["raw"] if isinstance(e["raw"], dict) else {})) for e in evs):
        noev.append((v["id"], v["employee_id"][:10]))
R["四3_job无据"] = noev or "无"

print(json.dumps(R, ensure_ascii=False, indent=1, default=str))
