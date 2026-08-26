# -*- coding: utf-8 -*-
import sqlite3
db = sqlite3.connect("/app/data/ipguard.db", timeout=60)
db.row_factory = sqlite3.Row
rows = db.execute("""SELECT id, employee_id, scenario, risk_score, status, substr(window_start,1,10) d, substr(summary,1,90) sm
FROM alerts ORDER BY status='NEW' DESC, risk_score DESC, id""").fetchall()
out = ["TOTAL %d" % len(rows)]
for a in rows:
    out.append('[%d]%s|%s|%d|%s|%s|%s' % (a["id"], a["employee_id"][:10], a["scenario"][:12], a["risk_score"],
                                          a["status"][:4], a["d"], (a["sm"] or "").replace(" ", "")))
open("/tmp/now.txt", "w", encoding="utf-8").write("\n".join(out))
print(len(rows))
