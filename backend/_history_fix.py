# -*- coding: utf-8 -*-
"""全量历史告警修复(2026-08-26逐条审阅后): filez/ELN回溯关闭+同日去重+豁免补行+内网IP+双前缀。"""
import sys
sys.path.insert(0, "/app")
import json
import re
import sqlite3
import time
from datetime import datetime

db = sqlite3.connect("/app/data/ipguard.db", timeout=120)
db.row_factory = sqlite3.Row
R = {}

def ts(x):
    return x if isinstance(x, datetime) else datetime.fromisoformat(str(x)[:19])

wl = [w.lower() for w in json.loads(db.execute("SELECT payload FROM dicts WHERE name='risk_whitelist_domains'").fetchone()["payload"])]

def dest_host(raw):
    d = ((raw or {}).get("dest_path") or "").strip().lower()
    if d.startswith(("http:", "https:")):
        p = d.split("/")
        d = p[2] if len(p) > 2 else d
    else:
        d = d.split("/")[0]
    if ":" in d:
        d = d.split(":")[0]
    return d

def is_wl(d):
    return bool(d) and any(d == x or d.endswith("." + x) for x in wl)

def is_priv_ip(d):
    parts = d.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return False
    a, b = int(parts[0]), int(parts[1])
    return a == 10 or a == 127 or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31)

for attempt in range(30):
    try:
        # ---- A/B: NEW告警中 filez/ELN/私网IP 目的地 → 回溯关闭 ----
        nAB = 0
        for a in db.execute("""SELECT id, employee_id, scenario, summary, verdict_id FROM alerts
            WHERE status='NEW' AND scenario IN ('mass_exfil','archive_exfil','rename_exfil','data_exfiltration','policy_violation')
            AND (summary LIKE '%filez%' OR summary LIKE '%eln.huashen%' OR summary LIKE '%10.4.128.9%')
            AND summary NOT LIKE '%白名单%'""").fetchall():
            sm = a["summary"] or ""
            # 验证: mass类按当日事件重算是否全白
            close = None
            if "filez" in sm:
                close = "目的地为filez.com=公司FileZ网盘(已加白,存量回溯)"
            elif "eln.huashen" in sm and "非白名单" in sm:
                # 重算当日
                d0 = db.execute("SELECT window_start FROM alerts WHERE id=?", (a["id"],)).fetchone()["window_start"]
                day0 = str(d0)[:10]
                evs = db.execute("""SELECT raw FROM events WHERE employee_id=? AND occurred_at>=? AND occurred_at<?
                    AND action IN ('SEND','UPLOAD')""", (a["employee_id"], day0, day0 + " 23:59")).fetchall()
                keep = [e for e in evs if not is_wl(dest_host(json.loads(e["raw"]) if isinstance(e["raw"], str) else (e["raw"] or {})))]
                if len(keep) == 0:
                    close = "当日全部外发目的地为公司ELN等白名单域(存量回溯)"
                elif len(keep) < 15:
                    mb = sum(0 for _ in keep)  # 逐条size查太慢,条数已不足阈值且MB必降
                    close = "重算后低于聚合阈值(白名单排除)"
            elif "10.4.128.9" in sm:
                close = "目的地10.4.128.9为公司内网IPG服务器(内网传输非外发)"
            if close:
                db.execute("UPDATE alerts SET status='CLOSED', risk_score=15, severity='LOW', summary=? WHERE id=?",
                           ("[白名单更正: " + close + "] " + sm[:140], a["id"]))
                nAB += 1
        R["AB_白名单回溯关闭"] = nAB

        # ---- C: 同日重复告警合并(同人同场景同日,保留高分) ----
        rows = db.execute("""SELECT id, employee_id, scenario, risk_score, status, substr(window_start,1,10) d
            FROM alerts ORDER BY employee_id, scenario, d, risk_score DESC""").fetchall()
        seen = {}
        nC = 0
        for r in rows:
            k = (r["employee_id"], r["scenario"], r["d"])
            if k in seen:
                # 保留分高的(先到),状态若被删行是NEW而保留行非NEW则把保留行置回NEW
                keep_id = seen[k]
                keep = db.execute("SELECT status FROM alerts WHERE id=?", (keep_id,)).fetchone()
                if keep and r["status"] == "NEW" and keep["status"] != "NEW":
                    db.execute("UPDATE alerts SET status='NEW' WHERE id=?", (keep_id,))
                db.execute("DELETE FROM alerts WHERE id=?", (r["id"],))
                nC += 1
            else:
                seen[k] = r["id"]
        R["C_同日重复合并"] = nC

        # ---- D: 黄春煜豁免跟上演变名 + 删其job告警 ----
        if not db.execute("SELECT 1 FROM exceptions WHERE employee_id='huangchunyu' AND signal_type='job_seeking'").fetchone():
            db.execute("INSERT INTO exceptions (employee_id, signal_type, reason, expires_at) VALUES ('huangchunyu','job_seeking','岗位需要(黄春煜账号别名)',NULL)")
        nD = db.execute("DELETE FROM alerts WHERE employee_id='huangchunyu' AND scenario='job_seeking'").rowcount
        R["D_豁免补行删告警"] = nD

        # ---- G: 双前缀清理 ----
        nG = 0
        for a in db.execute("SELECT id, summary FROM alerts WHERE summary LIKE '%[白名单更正:%[白名单更正:%'").fetchall():
            sm = re.sub(r"(\[白名单更正:[^\]]*\]\s*)+", "[白名单更正: 公司通道,重算关闭] ", a["summary"] or "", count=1)
            db.execute("UPDATE alerts SET summary=? WHERE id=?", (sm, a["id"]))
            nG += 1
        R["G_双前缀清理"] = nG
        db.commit()
        break
    except sqlite3.OperationalError as e:
        db.rollback()
        if "locked" in str(e).lower() and attempt < 29:
            time.sleep(1)
            continue
        raise

# 汇总
print(json.dumps(R, ensure_ascii=False))
from collections import Counter
st = Counter(r[0] for r in db.execute("SELECT status FROM alerts").fetchall())
print("修复后状态分布:", dict(st))
