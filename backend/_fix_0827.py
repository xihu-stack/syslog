import sqlite3, time, re
db = sqlite3.connect("/app/data/ipguard.db", timeout=60)
db.row_factory = sqlite3.Row
def sv(sc): return "CRITICAL" if sc>=76 else "HIGH" if sc>=56 else "MEDIUM" if sc>=31 else "LOW"
for attempt in range(30):
    try:
        # 1) guofei [299]分对齐
        v = db.execute("SELECT risk_score FROM verdicts WHERE id=(SELECT verdict_id FROM alerts WHERE id=299)").fetchone()
        if v:
            db.execute("UPDATE alerts SET risk_score=?, severity=? WHERE id=299", (v[0], sv(v[0])))
            print("299对齐:", v[0])
        # 2) severity统一
        for a in db.execute("SELECT id, risk_score, severity FROM alerts").fetchall():
            if a["severity"] != sv(a["risk_score"]):
                db.execute("UPDATE alerts SET severity=? WHERE id=?", (sv(a["risk_score"]), a["id"]))
        # 3) hlx: 非中文账号有outlook.live访问但7天只1次verdict——检查是否有豁免需求
        # (hlx是企业缩写账号,6次邮箱访问但只有1次研判,需确认是否在忽略名单)
        ign = db.execute("SELECT value FROM settings WHERE key='ignore_employees'").fetchone()
        print("hlx忽略状态:", ign[0][:50] if ign and ign[0] else "(空)")
        db.commit()
        break
    except sqlite3.OperationalError:
        db.rollback(); time.sleep(1)
# 验证
m = sum(1 for a in db.execute("SELECT id, employee_id, risk_score, verdict_id, summary FROM alerts WHERE verdict_id IS NOT NULL").fetchall()
        if (v := db.execute("SELECT employee_id, risk_score FROM verdicts WHERE id=?", (a["verdict_id"],)).fetchone())
        and v["employee_id"]==a["employee_id"] and not re.search(r"次日复核|N\+1复核|研判已降至|白名单|巡检|豁免|历史|复犯重开", a["summary"] or "")
        and a["risk_score"]!=v["risk_score"])
s = sum(1 for a in db.execute("SELECT risk_score, severity FROM alerts").fetchall() if a["severity"]!=sv(a["risk_score"]))
print("终验: 分不一致=", m, "severity错=", s)
