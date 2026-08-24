"""业务数据审计(只读): 14项跨表/语义不变量。"""
import sys
sys.path.insert(0, "/app")
import json
import re
import sqlite3
from datetime import datetime

db = sqlite3.connect("/app/data/ipguard.db")
db.row_factory = sqlite3.Row
q1 = lambda sql, *a: db.execute(sql, a).fetchone()[0]
now = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
R = {}

# 1) 幽灵告警: 窗口[window_start-30min, +3h]内该员工无任何事件
rows = db.execute("SELECT id, employee_id, window_start FROM alerts").fetchall()
ghost = []
for a in rows:
    ws = str(a["window_start"])[:19]
    n = q1("SELECT COUNT(*) FROM events WHERE employee_id=? AND occurred_at BETWEEN datetime(?,'-30 minutes') AND datetime(?,'+3 hours')",
           a["employee_id"], ws, ws)
    if n == 0:
        ghost.append((a["id"], a["employee_id"][:12], ws[:16]))
R["1_幽灵告警"] = ghost[:15] + ([f"...共{len(ghost)}"] if len(ghost) > 15 else [])

# 2) verdict event_hashes 悬空
import hashlib  # noqa
bad_hash = 0
tot_v = 0
for v in db.execute("SELECT id, event_hashes FROM verdicts WHERE event_hashes IS NOT NULL").fetchall():
    hs = v["event_hashes"] or []
    if not isinstance(hs, list):
        continue
    tot_v += 1
    if hs:
        ph = ",".join("?" * len(hs))
        n = db.execute(f"SELECT COUNT(*) FROM events WHERE event_hash IN ({ph})", hs).fetchone()[0]
        if n < len(hs) * 0.5:  # 过半解析失败=悬空
            bad_hash += 1
R["2_研判悬空引用"] = f"{bad_hash}/{tot_v} 条过半hash解析失败"

# 3) dedup_key 重复
dup = db.execute("""SELECT dedup_key, COUNT(*) c FROM alerts WHERE dedup_key IS NOT NULL
GROUP BY dedup_key HAVING c>1""").fetchall()
R["3_dedup重复"] = [(d["dedup_key"], d["c"]) for d in dup[:10]] or "无"

# 4) 未来时间
R["4_未来时间"] = {
    "alerts": q1("SELECT COUNT(*) FROM alerts WHERE window_start > ?", now),
    "verdicts": q1("SELECT COUNT(*) FROM verdicts WHERE window_start > ?", now),
    "events": q1("SELECT COUNT(*) FROM events WHERE occurred_at > ?", now),
}

# 5) NEW告警<50 / severity错档
R["5_阈值与档位"] = {
    "NEW_lt50": q1("SELECT COUNT(*) FROM alerts WHERE status='NEW' AND risk_score<50"),
    "severity错档": db.execute("""SELECT COUNT(*) FROM alerts WHERE
        (risk_score>=76 AND severity NOT IN ('CRITICAL','crit')) OR
        (risk_score BETWEEN 56 AND 75 AND severity!='HIGH') OR
        (risk_score BETWEEN 31 AND 55 AND severity!='MEDIUM') OR
        (risk_score<31 AND severity!='LOW')""").fetchone()[0],
}

# 6) 前缀与状态矛盾
R["6_前缀状态矛盾"] = [
    ("自动关闭但NEW", q1("SELECT COUNT(*) FROM alerts WHERE summary LIKE '%自动关闭%' AND status='NEW'")),
    ("N+1复核前缀但状态NEW且分>=76无说明", q1("SELECT COUNT(*) FROM alerts WHERE summary LIKE '[N+1复核%' AND status='NEW' AND risk_score>=76")),
]

# 7) CONFIRMED/FP 无feedback留痕
R["7_处置无留痕"] = q1("""SELECT COUNT(*) FROM alerts a WHERE a.status IN ('CONFIRMED','FP')
AND NOT EXISTS (SELECT 1 FROM feedback f WHERE f.alert_id=a.id)""")

# 8) 豁免但该场景仍有NEW告警
viol8 = db.execute("""SELECT a.id, a.employee_id, a.scenario FROM alerts a
JOIN exceptions e ON e.employee_id=a.employee_id AND e.signal_type=a.scenario
WHERE a.status='NEW' AND (e.expires_at IS NULL OR e.expires_at > ?)""", (now,)).fetchall()
R["8_豁免仍NEW"] = [(v["id"], v["employee_id"][:10], v["scenario"]) for v in viol8[:10]] or "无"

# 9) 画像基线污染: common_domains 含风险域名
RISK_PAT = re.compile(r"(zhipin|liepin|51job|zhaopin|filehelper|weixin\.qq\.com/file|pan\.baidu|outlook\.live|outlook\.office\.com|gmail|mail\.163|mail\.qq|todesk|sunlogin|github)", re.I)
pol = []
for p in db.execute("SELECT employee_id, payload FROM profiles").fetchall():
    try:
        doms = (json.loads(p["payload"]) or {}).get("common_domains") or []
    except Exception:
        continue
    hit = [d for d in doms if RISK_PAT.search(str(d))]
    if hit:
        pol.append((p["employee_id"][:12], hit[:3]))
R["9_基线污染"] = pol[:10] + ([f"...共{len(pol)}人"] if len(pol) > 10 else []) or "无"

# 10) mass_exfil 数字复算(抽5条: 员工当日 SEND/UPLOAD 次数与总量)
mass = db.execute("SELECT id, employee_id, summary, window_start FROM alerts WHERE scenario='mass_exfil' ORDER BY window_start DESC LIMIT 5").fetchall()
chk10 = []
for m in mass:
    day = str(m["window_start"])[:10]
    mm = re.search(r"累计外发(\d+)次\(共([\d.]+)MB\)", m["summary"] or "")
    if not mm:
        chk10.append((m["id"], "摘要无可解析数字")); continue
    cnt = q1("SELECT COUNT(*) FROM events WHERE employee_id=? AND occurred_at>=? AND occurred_at<? AND action IN ('SEND','UPLOAD')", m["employee_id"], day, day + " 23:59")
    sz = q1("SELECT COALESCE(SUM(size_bytes),0) FROM events WHERE employee_id=? AND occurred_at>=? AND occurred_at<? AND action IN ('SEND','UPLOAD')", m["employee_id"], day, day + " 23:59")
    chk10.append((m["id"], m["employee_id"][:10], day, f"摘要={mm.group(1)}次/{mm.group(2)}MB", f"事件={cnt}次/{round((sz or 0)/1048576,1)}MB"))
R["10_mass数字复算"] = chk10

# 11) job告警无招聘证据(近7天无招聘域名事件)
JOB_DOM = re.compile(r"(zhipin|liepin|51job|zhaopin|maimai|kanzhun|zhuopin|italent|liepin)", re.I)
noev = []
for a in db.execute("SELECT id, employee_id FROM alerts WHERE scenario='job_seeking' AND status='NEW'").fetchall():
    evs = db.execute("""SELECT (raw->>'domain') d FROM events WHERE employee_id=? AND occurred_at>=datetime('now','-7 days') AND category='WEB'""", (a["employee_id"],)).fetchall()
    if not any(e["d"] and JOB_DOM.search(e["d"]) for e in evs):
        noev.append((a["id"], a["employee_id"][:12]))
R["11_job无据"] = noev[:10] or "无"

# 12) 同一AGT对应多身份
agts = json.loads(db.execute("SELECT value FROM settings WHERE key='ipg_agt_map'").fetchone()[0])
from collections import defaultdict
by_agt = defaultdict(set)
ev_emp = {r[0] for r in db.execute("SELECT DISTINCT employee_id FROM events")}
for agt_id, person in agts.items():
    p = str(person)
    by_agt[p].add(agt_id)
# 碎片化: 中文名员工与拼音账号都活跃且同AGT — 用中文名员工的姓拼不出来,改查: 中文名与拼音账号都活跃且该拼音有AGT且该AGT的IPG:占位也在
frag = []
for cn in [e for e in ev_emp if re.search(r"[\u4e00-\u9fff]", e or "")]:
    pass
# 简化: IPG:xxx占位 与其关联账号并存(同机器双身份)
ipg_ids = [e for e in ev_emp if e and e.startswith("IPG:")]
both = [(x, agts.get(x[4:])) for x in ipg_ids if agts.get(x[4:]) and agts.get(x[4:]) in ev_emp]
R["12_同机双身份"] = both[:12] + ([f"...共{len(both)}"] if len(both) > 12 else []) or "无"

# 13) CLOSED且>=76且无复核标记
R["13_高分关闭无标记"] = db.execute("""SELECT COUNT(*) FROM alerts WHERE status='CLOSED' AND risk_score>=76
AND summary NOT LIKE '[%'""").fetchone()[0]

# 14) verdict窗口倒置
R["14_窗口倒置"] = q1("SELECT COUNT(*) FROM verdicts WHERE window_end IS NOT NULL AND window_end < window_start")

print(json.dumps(R, ensure_ascii=False, indent=1, default=str))
