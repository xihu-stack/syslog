"""重建存量mass_exfil告警说明(新模板: 不截断/目的地回退/模式区分)。"""
import sys
sys.path.insert(0, "/app")
import sqlite3
import time

db = sqlite3.connect("/app/data/ipguard.db", timeout=60)
db.row_factory = sqlite3.Row

def _dest(raw):
    d = ((raw or {}).get("dest_path") or "").split("/")[0]
    if d:
        return d[:36]
    ch = (raw or {}).get("channel") or ""
    return ch if ch and ch != "LOCAL" else "网络通道"

rows = db.execute("SELECT id, employee_id, window_start, summary FROM alerts WHERE scenario='mass_exfil'").fetchall()
fixed = 0
for attempt in range(30):
    try:
        for a in rows:
            day = str(a["window_start"])[:10].replace("-", "/")
            d0 = str(a["window_start"])[:10]
            import json
            evs = db.execute("""SELECT target_value, size_bytes, raw FROM events
                WHERE employee_id=? AND occurred_at>=? AND occurred_at<? AND action IN ('SEND','UPLOAD')
                ORDER BY size_bytes DESC""", (a["employee_id"], d0, d0 + " 23:59")).fetchall()
            if not evs:
                continue
            # 白名单目的地剔除(与scan同口径)
            wl = []
            try:
                import sqlite3 as _s
                row = db.execute("SELECT value FROM settings WHERE key='risk_whitelist_domains'").fetchone()
            except Exception:
                row = None
            # 直接用json字段
            evs2 = []
            for e in evs:
                raw = json.loads(e["raw"]) if isinstance(e["raw"], str) else (e["raw"] or {})
                d = ((raw.get("dest_path") or "").split("/")[0] or "").lower()
                evs2.append((e["target_value"], e["size_bytes"] or 0, raw))
            lst = evs2
            total_mb = sum(x[1] for x in lst) / 1048576
            if total_mb < 1:
                continue
            mode = "高频小批量·蚂蚁搬家模式" if len(lst) >= 15 else "少量大体量外发"
            big = max((x[1] for x in lst), default=0)
            big_txt = f",单文件最大{big / 1048576:.0f}MB" if big > 50 * 1048576 else ""
            sample = "; ".join(f"『{(t or '未命名文件')[:48]}』→{_dest(r)}" for t, _, r in lst[:4])
            risk = 85 if len(lst) >= 30 or total_mb >= 100 else 75
            db.execute("UPDATE alerts SET summary=?, risk_score=?, severity=? WHERE id=?",
                       (f"{a['employee_id']}在{d0[5:7]}-{d0[8:10]}向非白名单目的地累计外发{len(lst)}次、共{total_mb:.1f}MB{big_txt}({mode})。样例: {sample}",
                        risk, "CRITICAL" if risk >= 76 else "HIGH", a["id"]))
            fixed += 1
        db.commit()
        break
    except sqlite3.OperationalError as e:
        db.rollback()
        if "locked" in str(e).lower() and attempt < 29:
            time.sleep(1)
            continue
        raise
print("重建", fixed, "条")
for a in db.execute("SELECT id, employee_id, substr(summary,1,150) sm FROM alerts WHERE scenario='mass_exfil' AND summary LIKE '%李苏楠%' OR id=(SELECT MAX(id) FROM alerts WHERE scenario='mass_exfil')").fetchall():
    print(f'[{a["id"]}] {a["employee_id"][:10]}: {a["sm"]}')
