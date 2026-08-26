# -*- coding: utf-8 -*-
"""精准度修复: 深信服可恢复的目的地/截断箭头/大小补充。"""
import sys, json, re, sqlite3, time
from datetime import datetime
sys.path.insert(0, "/app")
import dicts

db = sqlite3.connect("/app/data/ipguard.db", timeout=120)
db.row_factory = sqlite3.Row
R = {}

for attempt in range(30):
    try:
        # ===== 1. 深信服可恢复的目的地→关闭/补充 =====
        n1 = 0
        for a in db.execute("""SELECT id, employee_id, window_start, verdict_id, summary FROM alerts
            WHERE status='NEW' AND summary LIKE '%目的地未记录%'""").fetchall():
            if not a["verdict_id"]: continue
            v = db.execute("SELECT event_hashes FROM verdicts WHERE id=?", (a["verdict_id"],)).fetchone()
            if not v: continue
            hs = v["event_hashes"] or []
            if isinstance(hs, str): hs = json.loads(hs)
            if not hs: continue
            ph = ",".join("?" * len(hs))
            sends = db.execute(f"""SELECT occurred_at, raw FROM events WHERE event_hash IN ({ph})
                AND category='DOC' AND action IN ('SEND','UPLOAD') AND json_extract(raw,'$.dest_path')=''""", hs).fetchall()
            all_wl = True
            recovered_doms = []
            for se in sends:
                raw = json.loads(se["raw"]) if isinstance(se["raw"], str) else (se["raw"] or {})
                if dicts.whitelisted_dest(raw):
                    recovered_doms.append("白名单")
                    continue
                webs = db.execute("""SELECT json_extract(raw,'$.domain') d FROM events
                    WHERE employee_id=? AND category='WEB' AND source!='ipguard'
                    AND occurred_at BETWEEN datetime(?,'-5 minutes') AND datetime(?,'+5 minutes')
                    LIMIT 5""", (a["employee_id"], str(se["occurred_at"])[:19], str(se["occurred_at"])[:19])).fetchall()
                found = None
                for w in webs:
                    if w["d"]:
                        if dicts.whitelisted_dest({"dest_path": "https://" + w["d"]}):
                            found = w["d"]
                            break
                        found = found or w["d"]
                if found and dicts.whitelisted_dest({"dest_path": "https://" + found}):
                    recovered_doms.append(found)
                else:
                    all_wl = False
                    if found:
                        recovered_doms.append(f"{found}(非白)")
            if all_wl and sends:
                db.execute("""UPDATE alerts SET status='CLOSED', risk_score=15, severity='LOW',
                    summary='[白名单更正: 深信服延迟数据已到,同时刻浏览为公司白名单域名(teams/M365/xft等),实为公司通道] '
                    ||substr(summary,1,130) WHERE id=?""", (a["id"],))
                n1 += 1
            elif recovered_doms and "→" in (a["summary"] or ""):
                # 有恢复的目的地→补充到说明
                dom_txt = ", ".join(recovered_doms[:3])
                sm2 = (a["summary"] or "").replace("目的地未记录(网页上传)", f"推断目的地:{dom_txt}(深信服)")
                if sm2 != (a["summary"] or ""):
                    db.execute("UPDATE alerts SET summary=? WHERE id=?", (sm2, a["id"]))
                    n1 += 1
        R["目的地恢复"] = n1

        # ===== 2. 截断箭头修复 =====
        n2 = 0
        for a in db.execute("SELECT id, summary FROM alerts WHERE status='NEW' AND (summary LIKE '%→;%' OR summary LIKE '%→→%')").fetchall():
            sm = (a["summary"] or "")
            sm2 = sm.replace("→;", "→未知;").replace("→→", "→未知→")
            # 移除连续"未知"冗余
            sm2 = re.sub(r"(→未知)+→", "→未知→", sm2)
            if sm2 != sm:
                db.execute("UPDATE alerts SET summary=? WHERE id=?", (sm2, a["id"]))
                n2 += 1
        R["截断箭头"] = n2

        # ===== 3. 外发类缺大小→查事件补充 =====
        n3 = 0
        for a in db.execute("""SELECT id, employee_id, window_start, verdict_id, summary FROM alerts
            WHERE status='NEW' AND scenario IN ('data_exfiltration','mass_exfil')
            AND summary LIKE '%发送%' AND summary NOT LIKE '%MB%' AND summary NOT LIKE '%大小%'
            AND summary NOT LIKE '%大小%' LIMIT 100""").fetchall():
            if not a["verdict_id"]: continue
            v = db.execute("SELECT event_hashes FROM verdicts WHERE id=?", (a["verdict_id"],)).fetchone()
            if not v: continue
            hs = v["event_hashes"] or []
            if isinstance(hs, str): hs = json.loads(hs)
            if not hs: continue
            ph = ",".join("?" * len(hs))
            sends = db.execute(f"""SELECT target_value, size_bytes FROM events WHERE event_hash IN ({ph})
                AND category='DOC' AND action IN ('SEND','UPLOAD') LIMIT 5""", hs).fetchall()
            total_mb = sum((s["size_bytes"] or 0) for s in sends) / 1048576
            if total_mb >= 0.1:
                sm2 = (a["summary"] or "") + f"(共{total_mb:.1f}MB)"
                db.execute("UPDATE alerts SET summary=? WHERE id=?", (sm2, a["id"]))
                n3 += 1
        R["补充大小"] = n3

        db.commit()
        break
    except sqlite3.OperationalError:
        db.rollback(); time.sleep(2)

print(json.dumps(R, ensure_ascii=False))

# 终验
issues = 0
for a in db.execute("SELECT summary FROM alerts WHERE status='NEW' LIMIT 400").fetchall():
    sm = a["summary"] or ""
    if "目的地未记录" in sm and "深信服" not in sm:
        issues += 1
    if "→;" in sm or "→→" in sm:
        issues += 1
print("终验残留精准度问题:", issues)
