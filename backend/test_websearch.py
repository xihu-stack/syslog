"""测试网页浏览 + 关键字搜索 的解析与检测（用独立临时库，不影响运行中的服务）。"""
import os
import sys
import tempfile

_tmp = os.path.join(tempfile.gettempdir(), "ipguard_test.db")
if os.path.exists(_tmp):
    os.remove(_tmp)
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}"  # 必须在 import db/pipeline 之前
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from collections import Counter

import pipeline
import profiles
from db import EventRow, Session, VerdictRow
from sqlalchemy import desc

n1 = pipeline.ingest_file(r"C:\Users\huxi\Desktop\111.xlsx")
n2 = pipeline.ingest_file(r"C:\Users\huxi\Desktop\222.xlsx")
profiles.build_profiles()
nv, na = pipeline.run_detection()

s = Session()
cats = Counter(r[0] for r in s.query(EventRow.category))
print(f"网页浏览 {n1} 条；关键字搜索 {n2} 条；分析窗口 {nv}；告警 {na}")
print("事件类型分布:", dict(cats))
emps = [r[0] for r in s.query(EventRow.employee_id).distinct()]
print("识别到的用户(按计算机名):", emps)
print("\n=== AI 判断（按风险降序，最多 15 条）===")
rows = s.query(VerdictRow).order_by(desc(VerdictRow.risk_score)).limit(15).all()
if not rows:
    print("  （无触发窗口——说明这批数据全是常规浏览/搜索，符合预期）")
for v in rows:
    print(f"  {v.employee_id:<14} 风险={v.risk_score:<3} 意图={v.intent:<20} {v.explanation}")
s.close()
