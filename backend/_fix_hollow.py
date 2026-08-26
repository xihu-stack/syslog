# -*- coding: utf-8 -*-
import sqlite3, json, time
from collections import Counter
db = sqlite3.connect("/app/data/ipguard.db", timeout=120)
db.row_factory = sqlite3.Row

def facts(hs):
    if isinstance(hs, str):
        hs = json.loads(hs)
    if not hs:
        return None
    ph = ",".join("?" * len(hs))
    evs = db.execute(f"SELECT category, action, raw FROM events WHERE event_hash IN ({ph})", hs).fetchall()
    acts = Counter(f"{e['category']}/{e['action']}" for e in evs if e["category"])
    doms = []
    for e in evs:
        if e["category"] == "WEB":
            d = ((json.loads(e["raw"]) if isinstance(e["raw"], str) else (e["raw"] or {})).get("domain") or "")[:30]
            if d and d not in doms:
                doms.append(d)
    at = "、".join(f"{k}×{n}" for k, n in acts.most_common(4))
    dt = (";域名: " + ", ".join(doms[:3])) if doms else ""
    return f"窗口行为: {at}{dt}。"

for attempt in range(30):
    try:
        na = nv = 0
        for a in db.execute("SELECT id, employee_id, window_start, verdict_id, summary FROM alerts WHERE summary LIKE '%存在%相关行为%'").fetchall():
            sm = a["summary"] or ""
            v = db.execute("SELECT id, event_hashes, intent FROM verdicts WHERE id=?", (a["verdict_id"],)).fetchone() if a["verdict_id"] else None
            f = facts(v["event_hashes"]) if v else None
            if f:
                sm2 = sm.replace(sm[sm.find("在"):sm.find("(系统按窗口事实生成)") + len("(系统按窗口事实生成)")], f"{a['employee_id']}{str(a['window_start'])[5:16]} {f}")
                db.execute("UPDATE alerts SET summary=? WHERE id=?", (sm2, a["id"]))
            else:
                db.execute("UPDATE alerts SET summary=REPLACE(summary,'存在数据外发相关行为(系统按窗口事实生成)','窗口含外发/风险访问行为,明细见研判历史') WHERE id=?", (a["id"],))
            na += 1
        for attempt2 in range(3):
            try:
                for v in db.execute("SELECT id, event_hashes, explanation FROM verdicts WHERE explanation LIKE '%存在%相关行为%' LIMIT 400").fetchall():
                    f = facts(v["event_hashes"])
                    ex = v["explanation"] or ""
                    if f:
                        ex2 = ex.replace(ex[ex.find("在"):ex.find("(系统按窗口事实生成)") + len("(系统按窗口事实生成)")], f)
                        db.execute("UPDATE verdicts SET explanation=? WHERE id=?", (ex2, v["id"]))
                    else:
                        db.execute("UPDATE verdicts SET explanation=REPLACE(explanation,'存在数据外发相关行为(系统按窗口事实生成)','含外发/风险访问行为') WHERE id=?", (v["id"],))
                    nv += 1
                db.commit()
                break
            except sqlite3.OperationalError:
                db.rollback(); time.sleep(2)
        db.commit()
        print(f"alerts重写{na} verdicts重写{nv}")
        break
    except sqlite3.OperationalError:
        db.rollback(); time.sleep(2)
# 验证
print("剩余空洞句:", db.execute("SELECT COUNT(*) FROM alerts WHERE summary LIKE '%存在%相关行为%'").fetchone()[0],
      db.execute("SELECT COUNT(*) FROM verdicts WHERE explanation LIKE '%存在%相关行为%'").fetchone()[0])
for r in db.execute("SELECT id, substr(summary,1,100) FROM alerts WHERE id IN (4,14,15)").fetchall():
    print("  ", tuple(r))
