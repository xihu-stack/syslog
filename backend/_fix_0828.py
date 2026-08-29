# -*- coding: utf-8 -*-
import sqlite3, time, re
db = sqlite3.connect("/app/data/ipguard.db", timeout=60)
db.row_factory = sqlite3.Row
def sv(sc): return "CRITICAL" if sc>=76 else "HIGH" if sc>=56 else "MEDIUM" if sc>=31 else "LOW"
for attempt in range(30):
    try:
        # 1) 沈睿[542]分对齐
        v = db.execute("SELECT risk_score FROM verdicts WHERE id=(SELECT verdict_id FROM alerts WHERE id=542)").fetchone()
        if v:
            db.execute("UPDATE alerts SET risk_score=?, severity=? WHERE id=542", (v[0], sv(v[0])))
            print("542对齐:", v[0])
        # 2) 卢延/顾婷婷: 有verdicts但无alert——查dedup key是否已有合并告警(CLOSED)
        for emp in ("卢延", "顾婷婷"):
            al = db.execute("SELECT id, status, dedup_key FROM alerts WHERE employee_id=? ORDER BY id DESC LIMIT 2", (emp,)).fetchall()
            for a in al:
                print(f"  {emp} [{a[0]}] status={a[1]} key={a[2][:30]}")
        db.commit()
        break
    except sqlite3.OperationalError:
        db.rollback(); time.sleep(1)
# 验证
m = 0
for a in db.execute("SELECT id, employee_id, risk_score, verdict_id, summary FROM alerts WHERE verdict_id IS NOT NULL").fetchall():
    v = db.execute("SELECT employee_id, risk_score FROM verdicts WHERE id=?", (a["verdict_id"],)).fetchone()
    if v and v["employee_id"]==a["employee_id"] and not re.search(r"次日复核|N\+1复核|研判已降至|白名单|巡检|豁免|历史|复犯重开", a["summary"] or "") and a["risk_score"]!=v["risk_score"]:
        m += 1
print("终验分不一致:", m)
