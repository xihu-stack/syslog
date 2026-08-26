# -*- coding: utf-8 -*-
"""全栈精准度审计: 找出所有影响告警说明精准度的残留缺口。只读。"""
import sys, json, re, sqlite3
from datetime import datetime, timedelta
from collections import Counter

db = sqlite3.connect("/app/data/ipguard.db", timeout=120)
db.row_factory = sqlite3.Row
R = {}

# ===== 1. 说明精准度检查 =====
print("== 1. 当前NEW告警说明精准度扫描 ==")
issues = Counter()
samples = {"无目的地": [], "无大小": [], "无通道": [], "套话": [], "截断箭头": []}
for a in db.execute("SELECT id, employee_id, summary FROM alerts WHERE status='NEW' LIMIT 400").fetchall():
    sm = a["summary"] or ""
    # 目的地缺失
    if "目的地未记录" in sm or "→未识别" in sm or ("SEND" not in sm and "外发" in sm and "→" not in sm):
        issues["无目的地"] += 1
        if len(samples["无目的地"]) < 2:
            samples["无目的地"].append((a["id"], sm[:80]))
    # 大小缺失(外发类但无MB信息)
    if ("外发" in sm or "发送" in sm or "上传" in sm) and "MB" not in sm and "文件" in sm:
        issues["无大小"] += 1
    # 通道不具体
    if re.search(r"通过网络(通道)?(发送|上传|外发)", sm) and "exe" not in sm and "微信" not in sm and "chrome" not in sm:
        issues["通道空泛"] += 1
        if len(samples["无通道"]) < 2:
            samples["无通道"].append((a["id"], sm[:80]))
    # 截断箭头
    if "→;" in sm or "→→" in sm or sm.rstrip().endswith("→"):
        issues["截断箭头"] += 1
        if len(samples["截断箭头"]) < 2:
            samples["截断箭头"].append((a["id"], sm[:80]))
    # 套话
    if "相关行为" in sm or "构成风险" in sm and "具体" not in sm:
        issues["套话"] += 1

print("  问题分布:", dict(issues))
for k, v in samples.items():
    if v:
        print(f"  {k}样例: {v[0]}")

# ===== 2. DOC事件是否丢失文件明细 =====
print("\n== 2. 窗口内DOC事件明细检查 ==")
# 抽3条最近研判,看窗口内DOC事件数 vs 说明中提到的文件数
for v in db.execute("""SELECT id, employee_id, event_hashes, explanation FROM verdicts
    WHERE event_hashes IS NOT NULL AND explanation LIKE '%发送%' OR explanation LIKE '%上传%'
    ORDER BY id DESC LIMIT 3""").fetchall():
    hs = v["event_hashes"] or []
    if isinstance(hs, str): hs = json.loads(hs)
    ph = ",".join("?" * len(hs)) if hs else "''"
    docs = db.execute(f"""SELECT action, target_value, size_bytes FROM events
        WHERE event_hash IN ({ph}) AND category='DOC' AND action IN ('SEND','UPLOAD')""", hs).fetchall() if hs else []
    files_in_expl = len(re.findall(r"『[^』]+』", v["explanation"] or ""))
    print(f"  [{v['id']}] {v['employee_id'][:8]}: 窗口{len(docs)}个SEND, 说明提到{files_in_expl}个文件", "✓" if files_in_expl >= min(len(docs), 3) else "⚠")

# ===== 3. 白名单遗漏(目的地在公司域但未命中) =====
print("\n== 3. 白名单命中检查(NEW外发告警) ==")
sys.path.insert(0, "/app")
import dicts
wl_miss = []
for a in db.execute("""SELECT id, employee_id, summary FROM alerts WHERE status='NEW'
    AND scenario IN ('data_exfiltration','mass_exfil') LIMIT 200""").fetchall():
    sm = a["summary"] or ""
    for m in re.finditer(r"→([a-zA-Z0-9\.\-]+)", sm):
        d = m.group(1).lower().rstrip(":").split(":")[0]
        if d and "." in d and not any(d == w or d.endswith("." + w) for w in (dicts.get("risk_whitelist_domains") or [])):
            if any(d.endswith(tld) for tld in (".huashen.bio", ".helixon.com", ".sharepoint.com", ".filez.com", ".live.com", ".cloud.microsoft")):
                wl_miss.append((a["id"], d))
if wl_miss:
    print("  疑似白名单遗漏:", wl_miss[:5])
else:
    print("  ✓ 无白名单遗漏")

# ===== 4. severity与分数对齐 =====
print("\n== 4. severity对齐 ==")
bad = db.execute("""SELECT COUNT(*) FROM alerts WHERE
    (risk_score>=76 AND severity NOT LIKE 'CRIT%') OR (risk_score BETWEEN 56 AND 75 AND severity NOT LIKE 'HIGH')
    OR (risk_score BETWEEN 31 AND 55 AND severity NOT LIKE 'MED%') OR (risk_score<31 AND severity NOT LIKE 'LOW')""").fetchone()[0]
print("  错档:", bad)

# ===== 5. 深信服延迟覆盖(目的地未记录的告警里,深信服数据是否已到) =====
print("\n== 5. 目的地未记录→深信服数据是否已到 ==")
unk = db.execute("""SELECT id, employee_id, window_start, verdict_id FROM alerts
    WHERE status='NEW' AND summary LIKE '%目的地未记录%' LIMIT 5""").fetchall()
recovered = 0
for a in unk:
    if not a["verdict_id"]: continue
    v = db.execute("SELECT event_hashes FROM verdicts WHERE id=?", (a["verdict_id"],)).fetchone()
    if not v: continue
    hs = v["event_hashes"] or []
    if isinstance(hs, str): hs = json.loads(hs)
    sends = db.execute("""SELECT occurred_at, raw FROM events WHERE event_hash IN ({})
        AND category='DOC' AND action IN ('SEND','UPLOAD') AND json_extract(raw,'$.dest_path')=''""".format(",".join("?"*len(hs))), hs).fetchall() if hs else []
    for se in sends:
        raw = json.loads(se["raw"]) if isinstance(se["raw"], str) else (se["raw"] or {})
        if dicts.whitelisted_dest(raw):
            recovered += 1
            break
        # 查±5分钟深信服
        webs = db.execute("""SELECT json_extract(raw,'$.domain') d FROM events
            WHERE employee_id=? AND category='WEB' AND source!='ipguard'
            AND occurred_at BETWEEN datetime(?,'-5 minutes') AND datetime(?,'+5 minutes')
            LIMIT 5""", (a["employee_id"], str(se["occurred_at"])[:19], str(se["occurred_at"])[:19])).fetchall()
        if webs:
            for w in webs:
                if w["d"] and dicts.whitelisted_dest({"dest_path": "https://" + w["d"]}):
                    recovered += 1
                    print(f"  [{a['id']}] {a['employee_id'][:8]} 深信服已到: {w['d'][:30]}=白名单")
                    break
            break
print(f"  目的地未记录: {len(unk)}条, 深信服可恢复: {recovered}条")
