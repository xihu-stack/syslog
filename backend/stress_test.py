"""并发压测：1 个研判(含多次 LLM) + 多个并发入库线程，验证不再 database is locked。用临时库。"""
import os
import sys
import tempfile
import threading
import time

_tmp = os.path.join(tempfile.gettempdir(), "stress.db")
if os.path.exists(_tmp):
    os.remove(_tmp)
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pipeline
from db import EventRow, Session

WEB, SEARCH = r"C:\Users\huxi\Desktop\111.xlsx", r"C:\Users\huxi\Desktop\222.xlsx"
errors = []
elock = threading.Lock()


def ingest_loop(path, times):
    for _ in range(times):
        try:
            pipeline.ingest_file(path)
        except Exception as e:
            with elock:
                errors.append(("ingest", str(e)))


def detect_once():
    try:
        pipeline.run_detection()
    except Exception as e:
        with elock:
            errors.append(("detect", str(e)))


pipeline.ingest_file(WEB)
pipeline.ingest_file(SEARCH)

threads = [threading.Thread(target=detect_once)]
for _ in range(3):
    threads.append(threading.Thread(target=ingest_loop, args=(WEB, 3)))
    threads.append(threading.Thread(target=ingest_loop, args=(SEARCH, 3)))

print(f"启动 {len(threads)} 个并发线程：1 研判(多次LLM) + {len(threads)-1} 入库 ...")
t0 = time.time()
for t in threads:
    t.start()
for t in threads:
    t.join()
dt = time.time() - t0

s = Session(); ev = s.query(EventRow).count(); s.close()
lock_errs = [e for e in errors if "locked" in e[1]]
print(f"\n耗时 {dt:.1f}s；库内事件 {ev}（应=40，去重生效）")
print(f"锁错误数: {len(lock_errs)}；总错误数: {len(errors)}")
if errors[:3]:
    print("错误样例:", errors[:3])
print("=> " + ("PASS 并发无锁冲突（研判与入库可并行）" if not lock_errs else "FAIL 仍出现 database is locked"))
