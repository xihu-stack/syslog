# -*- coding: utf-8 -*-
"""存量修复: 已模板化的说明→用全天事实+语义重写。"""
import sqlite3, json, re, time
from datetime import datetime
from collections import Counter

db = sqlite3.connect("/app/data/ipguard.db", timeout=120)
db.row_factory = sqlite3.Row

def ts(x):
    return x if isinstance(x, datetime) else datetime.fromisoformat(str(x)[:19])

import sys
sys.path.insert(0, "/app")
import dicts

for attempt in range(30):
    try:
        n = 0
        for a in db.execute("""SELECT id, employee_id, window_start, verdict_id, summary FROM alerts
            WHERE status='NEW' AND summary LIKE '%窗口行为:%'""").fetchall():
            sm = a["summary"] or ""
            v = db.execute("SELECT event_hashes, intent FROM verdicts WHERE id=?", (a["verdict_id"],)).fetchone() if a["verdict_id"] else None
            if not v:
                continue
            hs = v["event_hashes"] or []
            if isinstance(hs, str): hs = json.loads(hs)
            if not hs: continue
            ph = ",".join("?" * len(hs))
            evs = db.execute(f"SELECT * FROM events WHERE event_hash IN ({ph}) ORDER BY occurred_at", hs).fetchall()

            # 语义重写
            hr = ts(evs[0]["occurred_at"]).hour if evs else 12
            tod = "凌晨" if hr < 7 else ("深夜" if hr >= 22 else "工作时段")
            acts = Counter(f"{e['category']}/{e['action']}" for e in evs if e["category"])
            sends = []
            riskdoms = []
            for e in evs:
                raw = json.loads(e["raw"]) if isinstance(e["raw"], str) else (e["raw"] or {})
                if e["category"] == "DOC" and e["action"] in ("SEND", "UPLOAD"):
                    dh = dicts.dest_host(raw)
                    sends.append(f"『{(e['target_value'] or '')[:28]}』→{dh[:24] or '未识别'}")
                if e["category"] == "WEB":
                    d = (raw.get("domain") or "").lower()
                    if d and dicts.risk_class(d) and d not in riskdoms:
                        riskdoms.append(d)

            inten = {"data_exfiltration": "数据外发", "policy_violation": "违规",
                    "job_seeking": "求职", "baseline_deviation": "行为偏离",
                    "normal_work": "正常"}.get(v["intent"], v["intent"] or "")

            parts = [f"{a['employee_id']}在{str(a['window_start'])[5:16]}({tod})"]
            if sends:
                parts.append(f"外发{len(sends)}次: {'; '.join(sends[:3])}")
            if riskdoms:
                parts.append(f"风险域名: {', '.join(riskdoms[:3])}")
            if not sends and not riskdoms:
                at = "、".join(f"{k}×{c}" for k, c in acts.most_common(3))
                parts.append(f"行为: {at}")
            parts.append(f"属{inten}")

            sm2 = "。".join(parts) + "。"
            # 保留前缀
            for pf in ("[次日复核", "[N+1复核", "[重判后复核", "[切分研判"):
                if sm.startswith(pf):
                    _e = sm.find("]")
                    sm2 = sm[:_e+1] + " " + sm2
                    break
            db.execute("UPDATE alerts SET summary=? WHERE id=?", (sm2, a["id"]))
            n += 1
        db.commit()
        print("重写", n, "条模板化说明")
        # 样例
        for r in db.execute("SELECT id, substr(summary,1,100) FROM alerts WHERE id IN (474,473,471,263)").fetchall():
            print("  ", tuple(r))
        break
    except sqlite3.OperationalError:
        db.rollback(); time.sleep(2)
