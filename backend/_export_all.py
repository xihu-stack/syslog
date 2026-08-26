# -*- coding: utf-8 -*-
"""导出全部历史告警(逐条审阅用)。"""
import sqlite3
db = sqlite3.connect("/app/data/ipguard.db", timeout=60)
db.row_factory = sqlite3.Row
rows = db.execute("""SELECT id, employee_id, scenario, risk_score, status, window_start, summary
FROM alerts ORDER BY id""").fetchall()
out = ["TOTAL %d" % len(rows)]
for a in rows:
    sm = (a["summary"] or "").replace("\n", " ")
    out.append('[%d] %s|%s|%d分|%s|%s|%s' % (a["id"], a["employee_id"][:12], a["scenario"][:16],
                                             a["risk_score"], a["status"], str(a["window_start"])[:10], sm[:170]))
open("/tmp/all_alerts.txt", "w", encoding="utf-8").write("\n".join(out))
print("exported", len(rows))
