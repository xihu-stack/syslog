# -*- coding: utf-8 -*-
"""每日审计 2026-08-26 第二批: 定位明细。"""
import sys
sys.path.insert(0, "/app")
import json
import re
import sqlite3

db = sqlite3.connect("/app/data/ipguard.db", timeout=60)
db.row_factory = sqlite3.Row
q1 = lambda sql, *a: db.execute(sql, a).fetchone()[0]
PREFIX = re.compile(r"(次日复核|N\+1复核|研判已降至|白名单|巡检|豁免|历史|复犯重开)")

print("== A. 8条分不一致明细 ==")
for a in db.execute("SELECT id, employee_id, risk_score ar, verdict_id, summary FROM alerts WHERE verdict_id IS NOT NULL").fetchall():
    v = db.execute("SELECT employee_id, risk_score FROM verdicts WHERE id=?", (a["verdict_id"],)).fetchone()
    if v and v["employee_id"] == a["employee_id"] and not PREFIX.search(a["summary"] or "") and a["ar"] != v["risk_score"]:
        print(f'  [{a["id"]}] {a["employee_id"][:10]} alert={a["ar"]} verdict={v["risk_score"]} | {(a["summary"] or "")[:60]}')

print()
print("== B. severity错档分布 ==")
for r in db.execute("""SELECT severity, risk_score, COUNT(*) c FROM alerts GROUP BY severity, risk_score
HAVING (risk_score>=76 AND severity NOT LIKE 'CRIT%') OR (risk_score BETWEEN 56 AND 75 AND severity NOT LIKE 'HIGH') OR
(risk_score BETWEEN 31 AND 55 AND severity NOT LIKE 'MED%') OR (risk_score<31 AND severity NOT LIKE 'LOW') ORDER BY c DESC LIMIT 8""").fetchall():
    print(f'  severity={r["severity"]} score={r["risk_score"]} ×{r["c"]}')

print()
print("== C. 周逸飞外发时间线(近2天) ==")
for e in db.execute("""SELECT occurred_at, action, target_value, size_bytes, json_extract(raw,'$.dest_path') dp, json_extract(raw,'$.app') app
FROM events WHERE employee_id='周逸飞' AND action IN ('SEND','UPLOAD') AND occurred_at>=datetime('now','+8 hours','-2 days') ORDER BY occurred_at""").fetchall():
    print("  ", str(e["occurred_at"])[5:16], e["action"], (e["target_value"] or "")[:30], "→", (e["dp"] or "")[:40], f'{(e["size_bytes"] or 0)/1048576:.1f}MB', e["app"])

print()
print("== D. 胡曦近2天SEND明细+verdicts ==")
for e in db.execute("""SELECT occurred_at, target_value, json_extract(raw,'$.dest_path') dp FROM events
WHERE employee_id='胡曦' AND action IN ('SEND','UPLOAD') AND occurred_at>=datetime('now','+8 hours','-2 days') ORDER BY occurred_at""").fetchall():
    print("  ", str(e["occurred_at"])[5:16], (e["target_value"] or "")[:36], "→", (e["dp"] or "")[:36])
for v in db.execute("SELECT window_start, intent, risk_score FROM verdicts WHERE employee_id='胡曦' ORDER BY id DESC LIMIT 4").fetchall():
    print("  verdict:", str(v["window_start"])[:16], v["intent"], v["risk_score"])

print()
print("== E. sharepoint长域名完整形态 ==")
for r in db.execute("""SELECT json_extract(raw,'$.domain') d, COUNT(*) FROM events
WHERE category='WEB' AND json_extract(raw,'$.domain') LIKE '1717-ipv4%' LIMIT 2""").fetchall():
    print("  完整域名:", repr(r["d"]), "长度", len(r["d"] or ""))
import dicts
wl = [w.lower() for w in (dicts.get("risk_whitelist_domains") or [])]
d0 = q1("SELECT json_extract(raw,'$.domain') FROM events WHERE json_extract(raw,'$.domain') LIKE '1717-ipv4%' LIMIT 1")
print("  白名单含sharepoint.net:", "sharepoint.net" in wl, "| endswith匹配:", (d0 or "").lower().endswith(".sharepoint.net"))

print()
print("== F. IPG:65724/65999 残留事件与houshunan/hedi并存情况 ==")
for ipg, acct in (("IPG:65724", "houshunan"), ("IPG:65999", "hedi")):
    n1_ = q1("SELECT COUNT(*) FROM events WHERE employee_id=?", ipg)
    n2_ = q1("SELECT COUNT(*) FROM events WHERE employee_id=?", acct)
    print(f"  {ipg}:{n1_}条 | {acct}:{n2_}条 | 近2天{ipg}: ", q1("SELECT COUNT(*) FROM events WHERE employee_id=? AND occurred_at>=datetime('now','+8 hours','-2 days')", ipg))
