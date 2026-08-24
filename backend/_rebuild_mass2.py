"""存量mass_exfil重估(2026-08-24): 邻近白名单推断后重算次数/体量,
低于阈值关闭,存活的重建样例说明。"""
import sys
sys.path.insert(0, "/app")
import json
import re
import sqlite3
import time
from datetime import datetime, timedelta


def _ts(x):
    return x if isinstance(x, datetime) else datetime.fromisoformat(str(x)[:19])

db = sqlite3.connect("/app/data/ipguard.db", timeout=60)
db.row_factory = sqlite3.Row

wl = []
try:
    import dicts
    wl = [w.lower() for w in (dicts.get("risk_whitelist_domains") or [])]
except Exception:
    row = db.execute("SELECT value FROM dicts WHERE name='risk_whitelist_domains'").fetchone()
    wl = [w.lower() for w in (json.loads(row["payload"]) if row else [])]

alerts = db.execute("SELECT id, employee_id, window_start, status FROM alerts WHERE scenario='mass_exfil'").fetchall()
out = {"closed": [], "kept": []}
for attempt in range(30):
    try:
        for a in alerts:
            d0 = str(a["window_start"])[:10]
            evs = db.execute("""SELECT id, occurred_at, target_value, size_bytes, raw FROM events
                WHERE employee_id=? AND occurred_at>=? AND occurred_at<? AND action IN ('SEND','UPLOAD')""",
                (a["employee_id"], d0, d0 + " 23:59")).fetchall()
            webs = db.execute("""SELECT occurred_at, raw FROM events
                WHERE employee_id=? AND occurred_at>=? AND occurred_at<? AND category='WEB'""",
                (a["employee_id"], d0, d0 + " 23:59")).fetchall()
            wlist = []
            for w in webs:
                raw = json.loads(w["raw"]) if isinstance(w["raw"], str) else (w["raw"] or {})
                d = (raw.get("domain") or "").lower()
                if d:
                    wlist.append((_ts(w["occurred_at"]), d))
            wlist.sort()

            def near(ts):
                hit, doms = False, []
                for t, d in wlist:
                    if abs((t - ts).total_seconds()) > 180:
                        continue
                    if any(d == x or d.endswith("." + x) for x in wl):
                        hit = True
                    elif d not in doms:
                        doms.append(d)
                return hit, doms

            kept, inferred = [], {}
            for e in evs:
                raw = json.loads(e["raw"]) if isinstance(e["raw"], str) else (e["raw"] or {})
                dest = (raw.get("dest_path") or "").strip().lower()
                if dest.startswith(("http:", "https:")):
                    _p = dest.split("/")
                    dest = _p[2] if len(_p) > 2 else dest
                else:
                    dest = dest.split("/")[0]
                if dest and any(dest == x or dest.endswith("." + x) for x in wl):
                    continue
                if not dest:
                    h, doms = near(_ts(e["occurred_at"]))
                    if h:
                        continue
                    if doms:
                        inferred[e["id"]] = doms[0][:36]
                kept.append((e, raw))
            total_mb = sum((e["size_bytes"] or 0) for e, _ in kept) / 1048576
            if len(kept) < 15 and total_mb < 50:
                db.execute("UPDATE alerts SET status='CLOSED', risk_score=15, severity='LOW', "
                           "summary='[白名单更正: 原计入的外发实为Teams/M365等公司通道传附件(邻近浏览域名推断),重算后低于聚合阈值] '||substr(summary,1,200) WHERE id=?", (a["id"],))
                out["closed"].append((a["id"], a["employee_id"][:10], len(kept), round(total_mb, 1)))
                continue
            mode = "高频小批量·蚂蚁搬家模式" if len(kept) >= 15 else "少量大体量外发"
            big = max(((e["size_bytes"] or 0) for e, _ in kept), default=0)
            big_txt = f",单文件最大{big / 1048576:.0f}MB" if big > 50 * 1048576 else ""

            def dest_of(e, raw):
                d = (raw.get("dest_path") or "").strip()
                if d.startswith(("http:", "https:")):
                    _p = d.split("/")
                    d = _p[2] if len(_p) > 2 else d
                else:
                    d = d.split("/")[0]
                if d:
                    return d[:36]
                if inferred.get(e["id"]):
                    return inferred[e["id"]] + "(同期浏览)"
                ch = raw.get("channel") or ""
                return (ch + "·未识别目的地") if ch and ch != "LOCAL" else "网络通道·未识别目的地"

            sample = "; ".join(f"『{(e['target_value'] or '未命名文件')[:48]}』→{dest_of(e, r)}" for e, r in kept[:4])
            risk = 85 if len(kept) >= 30 or total_mb >= 100 else 75
            db.execute("UPDATE alerts SET summary=?, risk_score=?, severity=? WHERE id=?",
                       (f"{a['employee_id']}在{d0[5:7]}-{d0[8:10]}向非白名单目的地累计外发{len(kept)}次、共{total_mb:.1f}MB{big_txt}({mode})。样例: {sample}",
                        risk, "CRITICAL" if risk >= 76 else "HIGH", a["id"]))
            out["kept"].append((a["id"], a["employee_id"][:10], len(kept), round(total_mb, 1)))
        db.commit()
        break
    except sqlite3.OperationalError as e:
        db.rollback()
        if "locked" in str(e).lower() and attempt < 29:
            time.sleep(1)
            continue
        raise
print(json.dumps(out, ensure_ascii=False, indent=1))
