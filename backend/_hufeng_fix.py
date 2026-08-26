# -*- coding: utf-8 -*-
import sqlite3, time
db = sqlite3.connect("/app/data/ipguard.db", timeout=60)
for attempt in range(30):
    try:
        for aid in (336, 425):
            a = db.execute("SELECT status, summary FROM alerts WHERE id=?", (aid,)).fetchone()
            if a and a[0] == "NEW":
                db.execute("""UPDATE alerts SET status='CLOSED', risk_score=15, severity='LOW',
                    summary='[白名单更正: 26次目的地为私网10.4.128.9(内网软件分发,有道词典/winrar等)+1次filez(公司网盘)+1次空目的地,非外发] '||substr(summary,1,130) WHERE id=?""", (aid,))
        db.commit()
        break
    except sqlite3.OperationalError:
        db.rollback(); time.sleep(1)
for r in db.execute("SELECT id, risk_score, status FROM alerts WHERE id IN (336,425)").fetchall():
    print(tuple(r))
