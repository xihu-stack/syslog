# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, "/app")
import re
import sqlite3

db = sqlite3.connect("/app/data/ipguard.db", timeout=60)
db.row_factory = sqlite3.Row
PREFIX = re.compile(r"(次日复核|N\+1复核|研判已降至|白名单|巡检|豁免|历史|复犯重开)")

print("== A. 分不一致8条 ==")
for a in db.execute("SELECT id, employee_id, risk_score ar, verdict_id, summary FROM alerts WHERE verdict_id IS NOT NULL").fetchall():
    v = db.execute("SELECT employee_id, risk_score FROM verdicts WHERE id=?", (a["verdict_id"],)).fetchone()
    if v and v["employee_id"] == a["employee_id"] and not PREFIX.search(a["summary"] or "") and a["ar"] != v["risk_score"]:
        print(f'  [{a["id"]}] {a["employee_id"][:10]} alert={a["ar"]} verdict={v["risk_score"]} | {(a["summary"] or "")[:56]}')

print("== B. severity错档TOP ==")
for r in db.execute("""SELECT severity, risk_score, COUNT(*) c FROM alerts
WHERE (risk_score>=76 AND severity NOT LIKE 'CRIT%') OR (risk_score BETWEEN 56 AND 75 AND severity NOT LIKE 'HIGH') OR
(risk_score BETWEEN 31 AND 55 AND severity NOT LIKE 'MED%') OR (risk_score<31 AND severity NOT LIKE 'LOW')
GROUP BY severity, risk_score ORDER BY c DESC LIMIT 8""").fetchall():
    print(f'  sev={r["severity"]} score={r["risk_score"]} ×{r["c"]}')

print("== 周逸飞 mass_exfil 行 ==")
for a in db.execute("SELECT id, dedup_key, risk_score, status, window_start, substr(summary,1,80) sm FROM alerts WHERE employee_id='周逸飞' AND scenario='mass_exfil'").fetchall():
    print(f'  [{a["id"]}] key={a["dedup_key"]} {a["risk_score"]}分 {a["status"]} win={str(a["window_start"])[:16]} | {a["sm"]}')

print("== 胡曦 alerts(全部) ==")
for a in db.execute("SELECT id, scenario, risk_score, status, window_start FROM alerts WHERE employee_id='胡曦' ORDER BY id DESC LIMIT 5").fetchall():
    print(f'  [{a["id"]}] {a["scenario"]} {a["risk_score"]}分 {a["status"]} {str(a["window_start"])[:16]}')
