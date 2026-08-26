# -*- coding: utf-8 -*-
import sqlite3, re, json, time
from datetime import datetime
db = sqlite3.connect("/app/data/ipguard.db", timeout=120)
db.row_factory = sqlite3.Row

def ts(x):
    return x if isinstance(x, datetime) else datetime.fromisoformat(str(x)[:19])

for attempt in range(30):
    try:
        # 1) 老键格式迁移: emp|scenario|MM-DD → emp|scenario|YYYY-MM-DD
        n1 = 0
        for a in db.execute("SELECT id, dedup_key, window_start FROM alerts WHERE dedup_key LIKE '%|__-__'").fetchall():
            dk = a["dedup_key"] or ""
            parts = dk.split("|")
            if len(parts) == 3 and len(parts[2]) == 5:
                full = str(a["window_start"])[:5] + parts[2]
                db.execute("UPDATE alerts SET dedup_key=? WHERE id=?", (f"{parts[0]}|{parts[1]}|{full}", a["id"]))
                n1 += 1
        # 2) 再去重
        rows = db.execute("""SELECT id, employee_id, scenario, risk_score, status, substr(window_start,1,10) d
            FROM alerts ORDER BY employee_id, scenario, d, risk_score DESC""").fetchall()
        seen, n2 = {}, 0
        for r in rows:
            k = (r["employee_id"], r["scenario"], r["d"])
            if k in seen:
                keep = db.execute("SELECT status FROM alerts WHERE id=?", (seen[k],)).fetchone()
                if keep and r["status"] == "NEW" and keep["status"] != "NEW":
                    db.execute("UPDATE alerts SET status='NEW' WHERE id=?", (seen[k],))
                db.execute("DELETE FROM alerts WHERE id=?", (r["id"],))
                n2 += 1
            else:
                seen[k] = r["id"]
        # 3) 胡峰内网IP两条(私网已入白名单规则)
        n3 = 0
        for aid in (336, 425):
            a = db.execute("SELECT id, status, summary, employee_id, window_start FROM alerts WHERE id=?", (aid,)).fetchone()
            if a and a["status"] == "NEW":
                d0 = str(a["window_start"])[:10]
                evs = db.execute("""SELECT raw FROM events WHERE employee_id=? AND occurred_at>=? AND occurred_at<?
                    AND action IN ('SEND','UPLOAD')""", (a["employee_id"], d0, d0 + " 23:59")).fetchall()
                import sys
                sys.path.insert(0, "/app")
                import dicts
                keep = [e for e in evs if not dicts.whitelisted_dest(json.loads(e["raw"]) if isinstance(e["raw"], str) else (e["raw"] or {}))]
                if len(keep) == 0:
                    db.execute("UPDATE alerts SET status='CLOSED', risk_score=15, severity='LOW', summary='[白名单更正: 目的地10.4.128.9等私网IP=内网传输(软件分发/有道词典等),非外发] '||substr(summary,1,140) WHERE id=?", (aid,))
                    n3 += 1
        # 4) [67]思维链前缀清洗
        n4 = 0
        for a in db.execute("SELECT id, summary FROM alerts WHERE summary LIKE '好，我现在%' OR summary LIKE '好的，我%'").fetchall():
            sm = re.sub(r"^(好[的，]?，?我现在需要[^。]*。|首先，[^。]*。)\s*", "", a["summary"] or "")
            db.execute("UPDATE alerts SET summary=? WHERE id=?", (sm, a["id"]))
            n4 += 1
        db.commit()
        print(json.dumps({"键迁移": n1, "再去重": n2, "胡峰关闭": n3, "思维链清洗": n4}, ensure_ascii=False))
        break
    except sqlite3.OperationalError as e:
        db.rollback()
        if "locked" in str(e).lower() and attempt < 29:
            time.sleep(1)
            continue
        raise
from collections import Counter
print("终态:", dict(Counter(r[0] for r in db.execute("SELECT status FROM alerts").fetchall())))
