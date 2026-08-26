# -*- coding: utf-8 -*-
"""独立视角: 08-26当日告警全面核查。只读。"""
import sqlite3, json, re
db = sqlite3.connect("/app/data/ipguard.db", timeout=60)
db.row_factory = sqlite3.Row

rows = db.execute("""SELECT id, employee_id, scenario, risk_score, severity, status, summary, window_start, verdict_id, dedup_key
FROM alerts WHERE window_start>='2026-08-26' ORDER BY risk_score DESC""").fetchall()
print("今日告警总数:", len(rows))
from collections import Counter
print("按状态:", dict(Counter(r["status"] for r in rows)))
print("按场景:", dict(Counter(r["scenario"] for r in rows)))
print()
print("===== A. 未处理且≥75分(逐条独立复核) =====")
for a in [r for r in rows if r["risk_score"] >= 75 and r["status"] == "NEW"]:
    v = db.execute("SELECT intent, risk_score, explanation FROM verdicts WHERE id=?", (a["verdict_id"],)).fetchone() if a["verdict_id"] else None
    print(f'[{a["id"]}] {a["risk_score"]}分 {a["scenario"][:16]:16s} {a["employee_id"][:12]:12s} win={str(a["window_start"])[11:16]} key={a["dedup_key"][:30]}')
    print("    ", (a["summary"] or "").replace(chr(10), " ")[:200])
    if v:
        print("    研判:", v["intent"], v["risk_score"], "|", (v["explanation"] or "")[:80])
print()
print("===== B. 未处理50-74分 =====")
for a in [r for r in rows if 50 <= r["risk_score"] < 75 and r["status"] == "NEW"]:
    print(f'[{a["id"]}] {a["risk_score"]}分 {a["scenario"][:16]:16s} {a["employee_id"][:12]} | {(a["summary"] or "")[:110]}')
print()
print("===== C. 今日已关闭(核对关闭原因) =====")
from collections import defaultdict
cls = defaultdict(list)
for a in [r for r in rows if r["status"] == "CLOSED"]:
    m = re.search(r"\[([^\]]{2,12})[^\]]*\]", a["summary"] or "")
    cls[m.group(1) if m else "无前缀"].append(a["id"])
for k, v2 in cls.items():
    print(f"  {k}: {len(v2)}条 {v2[:6]}")
print()
print("===== D. 今日新建聚合/模式类 =====")
for a in [r for r in rows if r["scenario"] in ("mass_exfil", "mass_delete", "archive_exfil", "rename_exfil", "trend_spike")]:
    print(f'[{a["id"]}] {a["risk_score"]}分 {a["status"]:7s} {a["scenario"]} {a["employee_id"][:10]} | {(a["summary"] or "")[:100]}')
