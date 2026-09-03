import sys, traceback
sys.path.insert(0, "/app")
import dicts
for k in ("llm_enabled", "llm_active", "llm_base_url"):
    v = dicts.get_setting(k)
    if v: print(f"{k}={str(v)[:40]}")
try:
    from llm_client import chat
    r = chat([{"role": "user", "content": "回复OK"}], max_tokens=5, timeout=15)
    print(f"LLM回复: {r[:20]}")
except Exception as e:
    print(f"LLM失败: {e}")
