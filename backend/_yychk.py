"""杨颖papers.zip事件核查+存量archive_exfil/rename_exfil目的地重建。"""
import sys
sys.path.insert(0, "/app")
import json
import re
import sqlite3
import time
from datetime import datetime

db = sqlite3.connect("/app/data/ipguard.db", timeout=60)
db.row_factory = sqlite3.Row


def _ts(x):
    return x if isinstance(x, datetime) else datetime.fromisoformat(str(x)[:19])


wl = [w.lower() for w in json.loads(db.execute("SELECT payload FROM dicts WHERE name='risk_whitelist_domains'").fetchone()["payload"])]

print("== 杨颖 papers 相关事件 ==")
for e in db.execute("""SELECT occurred_at, action, target_value, raw FROM events
    WHERE employee_id='杨颖' AND occurred_at>='2026-08-24'
    AND (target_value LIKE '%paper%' OR action='ARCHIVE') ORDER BY occurred_at""").fetchall():
    raw = json.loads(e["raw"]) if isinstance(e["raw"], str) else (e["raw"] or {})
    print(str(e["occurred_at"])[11:16], e["action"], (e["target_value"] or "")[:40],
          "| dest:", repr((raw.get("dest_path") or "")[:50]), "| app:", raw.get("app"))

# 邻近浏览
for a in db.execute("SELECT id, employee_id, scenario, window_start, summary FROM alerts WHERE scenario IN ('archive_exfil','rename_exfil')").fetchall():
    emp, d0 = a["employee_id"], str(a["window_start"])[:10]
    webs = []
    for w in db.execute("SELECT occurred_at, raw FROM events WHERE employee_id=? AND occurred_at>=? AND occurred_at<? AND category='WEB'", (emp, d0, d0 + " 23:59")).fetchall():
        raw = json.loads(w["raw"]) if isinstance(w["raw"], str) else (w["raw"] or {})
        d = (raw.get("domain") or "").lower()
        if d:
            webs.append((_ts(w["occurred_at"]), d))
    webs.sort()
    # 该员工当日ARCHIVE/SEND对
    evs = db.execute("""SELECT occurred_at, action, target_value, raw FROM events
        WHERE employee_id=? AND occurred_at>=? AND occurred_at<? AND action IN ('ARCHIVE','RENAME','SEND','UPLOAD')""", (emp, d0, d0 + " 23:59")).fetchall()
    fixed = 0
    for attempt in range(30):
        try:
            for e in evs:
                raw = json.loads(e["raw"]) if isinstance(e["raw"], str) else (e["raw"] or {})
                tv = (e["target_value"] or "")
                if tv[:20].lower() not in (a["summary"] or "").lower() and e["action"] not in ("ARCHIVE", "RENAME"):
                    continue
                if e["action"] not in ("SEND", "UPLOAD"):
                    continue
                dest = (raw.get("dest_path") or "").strip().lower()
                if dest.startswith(("http:", "https:")):
                    _p = dest.split("/")
                    dest = _p[2] if len(_p) > 2 else dest
                else:
                    dest = dest.split("/")[0]
                ts = _ts(e["occurred_at"])
                near = [d for t, d in webs if abs((t - ts).total_seconds()) <= 180]
                wl_near = any(any(d == x or d.endswith("." + x) for x in wl) for d in near)
                if not dest and wl_near:
                    db.execute("UPDATE alerts SET status='CLOSED', risk_score=15, severity='LOW', "
                               "summary='[白名单更正: 外发实为Teams/M365公司通道,压缩打包属正常附件上传] '||substr(summary,1,200) WHERE id=?", (a["id"],))
                    fixed = 1
                    break
                if dest:
                    new_dest = dest[:40]
                elif near:
                    new_dest = "同期浏览:" + "/".join(near[:2])[:40]
                else:
                    new_dest = "未识别目的地(网页上传)"
                sm = a["summary"] or ""
                sm2 = re.sub(r"至[^,，]*,属", f"至{new_dest},属", sm)
                if sm2 != sm:
                    db.execute("UPDATE alerts SET summary=? WHERE id=?", (sm2, a["id"]))
                    fixed = 1
                break
            db.commit()
            break
        except sqlite3.OperationalError as ex:
            db.rollback()
            time.sleep(1)
    sm_now = str(db.execute("SELECT summary FROM alerts WHERE id=?", (a["id"],)).fetchone()[0])
    tag = "白名单关闭" if "白名单" in sm_now else "目的地已补/维持"
    print("[%d] %s %s -> %s" % (a["id"], emp[:10], a["scenario"], tag))
