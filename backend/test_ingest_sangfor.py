"""验证 ingest_file 能自动识别深信服 CSV 并降噪聚合后落库。"""
import os
import sys
import tempfile

_tmp = os.path.join(tempfile.gettempdir(), "ig.db")
if os.path.exists(_tmp):
    os.remove(_tmp)
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pipeline
from db import EventRow, Session

n = pipeline.ingest_file(r"D:\代码\日志平台\samples\sangfor_sample.csv")
s = Session()
rows = s.query(EventRow).all()
s.close()
print(f"深信服 CSV（7条原始）→ 降噪聚合后落库 {n} 条（库内 {len(rows)}）:")
for r in rows:
    print(f"  {r.employee_id:<12} {r.target_value:<32} 次数={r.count} 分类={(r.raw or {}).get('category')}")
