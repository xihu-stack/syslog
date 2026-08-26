import sqlite3, json, sys
sys.path.insert(0, "/app")
import dicts
db = sqlite3.connect("/app/data/ipguard.db", timeout=60)
db.row_factory = sqlite3.Row
v = db.execute("SELECT id, event_hashes FROM verdicts WHERE employee_id='章晓萍' ORDER BY id DESC LIMIT 1").fetchone()
hs = v["event_hashes"] or []
if isinstance(hs, str): hs = json.loads(hs)
ph = ",".join("?" * len(hs))
print("窗口SEND构成:")
for e in db.execute(f"SELECT action, target_value, raw FROM events WHERE event_hash IN ({ph}) AND action IN ('SEND','UPLOAD')", hs).fetchall():
    raw = json.loads(e["raw"]) if isinstance(e["raw"], str) else (e["raw"] or {})
    dh = dicts.dest_host(raw)
    print("  ", e["action"], (e["target_value"] or "")[:30], "→", dh or "(空)", "| wl:", dicts.whitelisted_dest(raw))
