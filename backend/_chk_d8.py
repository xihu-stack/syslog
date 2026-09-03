import sys, json, sqlite3
sys.path.insert(0, "/app")
db = sqlite3.connect("/app/data/ipguard.db", timeout=60)
db.row_factory = sqlite3.Row
import dicts, re
# D8: 说明含外来域名
wl = [w.lower() for w in (dicts.get("risk_whitelist_domains") or [])]
for a in db.execute("SELECT id, employee_id, summary FROM alerts WHERE status='NEW' LIMIT 400").fetchall():
    sm = a["summary"] or ""
    for m in re.finditer(r"→([a-zA-Z0-9\-\.]+\.[a-z]{2,})", sm):
        d = m.group(1).lower().rstrip(":").split(":")[0]
        if d and "." in d and not any(d == w or d.endswith("." + w) for w in wl):
            if any(d.endswith(tld) for tld in (".huashen.bio", ".helixon.com", ".sharepoint.com", ".filez.com", ".live.com", ".cloud.microsoft", ".cmbchina.com")):
                print(f"D8: [{a[0]}] {a[1][:8]} →{d[:30]}")
# 一2: 用2天口径复查
print("== 一2 2天口径 ==")
for aid in (769, 764, 759):
    a = db.execute("SELECT id, employee_id, summary, window_start FROM alerts WHERE id=?", (aid,)).fetchone()
    d0 = str(a["window_start"])[:10]
    cnt = db.execute("SELECT COUNT(*) FROM events WHERE employee_id=? AND occurred_at>=datetime(?,'-1 day') AND occurred_at<? AND action IN ('SEND','UPLOAD')", (a["employee_id"], d0, d0 + " 23:59")).fetchone()[0]
    sz = db.execute("SELECT COALESCE(SUM(size_bytes),0) FROM events WHERE employee_id=? AND occurred_at>=datetime(?,'-1 day') AND occurred_at<? AND action IN ('SEND','UPLOAD')", (a["employee_id"], d0, d0 + " 23:59")).fetchone()[0]
    m = re.search(r"累计外发(\d+)次、共([\d.]+)MB", a["summary"] or "")
    print(f"  [{aid}] {a['employee_id'][:8]} 摘要={m.group(1)}/{m.group(2)}MB 实2天={cnt}/{sz/1048576:.1f}MB")
