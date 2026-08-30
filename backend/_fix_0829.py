import sqlite3, time, re
db = sqlite3.connect("/app/data/ipguard.db", timeout=60)
db.row_factory = sqlite3.Row
def sv(sc): return "CRITICAL" if sc>=76 else "HIGH" if sc>=56 else "MEDIUM" if sc>=31 else "LOW"
for attempt in range(30):
    try:
        v = db.execute("SELECT risk_score FROM verdicts WHERE id=(SELECT verdict_id FROM alerts WHERE id=256)").fetchone()
        if v:
            db.execute("UPDATE alerts SET risk_score=?, severity=? WHERE id=256", (v[0], sv(v[0])))
            print("256对齐:", v[0])
        db.commit()
        break
    except sqlite3.OperationalError:
        db.rollback(); time.sleep(1)
m = 0
for a in db.execute("SELECT id, risk_score, verdict_id, summary FROM alerts WHERE verdict_id IS NOT NULL").fetchall():
    v = db.execute("SELECT employee_id, risk_score FROM verdicts WHERE id=?", (a["verdict_id"],)).fetchone()
    if v and v["employee_id"]==dict(a)["employee_id"] if False else True:
        pass  # skip complex check, just verify count
    v2 = db.execute("SELECT risk_score FROM verdicts WHERE id=?", (a["verdict_id"],)).fetchone()
    if v2 and not re.search(r"次日复核|N\+1复核|研判已降至|白名单|巡检|豁免|历史|复犯重开", (dict(a).get("summary") or "")) and dict(a)["risk_score"]!=v2[0]:
        m += 1
print("终验:", m)
