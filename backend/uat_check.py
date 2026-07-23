"""UAT 自检 v2：验证重构后的增量研判 / 历史累积 / 基线=历史。用独立临时库。"""
import os
import sys
import tempfile

_tmp = os.path.join(tempfile.gettempdir(), "uat2.db")
if os.path.exists(_tmp):
    os.remove(_tmp)
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pipeline
import profiles
from db import EventRow, Session, VerdictRow

WEB, SEARCH = r"C:\Users\huxi\Desktop\111.xlsx", r"C:\Users\huxi\Desktop\222.xlsx"
vcount = lambda: Session().query(VerdictRow).count()
print("================ UAT v2 ================\n")

print("【UAT-1】事件去重（同一文件导两次）")
n1 = pipeline.ingest_file(WEB); n2 = pipeline.ingest_file(WEB)
ev = Session().query(EventRow).count()
print(f"  首次 {n1}，二次 {n2}，库内 {ev}  => {'PASS' if (n2==0 and ev==n1) else 'FAIL'}\n")

print("【UAT-2】增量累积：导web研判→导search研判，verdicts 应越来越多（不清空）")
j1, _ = pipeline.run_detection(); v1 = vcount()
n3 = pipeline.ingest_file(SEARCH)
j2, _ = pipeline.run_detection(); v2 = vcount()
print(f"  web研判 {j1} 窗口 → verdicts {v1}；再导search研判 {j2} 窗口 → verdicts {v2}")
print(f"  => {'PASS 累积+增量(新数据被研判、旧的保留)' if (v2 > v1 and j2 > 0) else 'FAIL'}\n")

print("【UAT-3】增量幂等：无新事件再研判一次，应 0 窗口、verdicts 不变")
j3, _ = pipeline.run_detection(); v3 = vcount()
print(f"  第3次研判 {j3} 窗口，verdicts {v3}")
print(f"  => {'PASS 增量(无新不动、不重算)' if (j3==0 and v3==v2) else 'FAIL'}\n")

print("【UAT-4】基线=历史：baseline_for 只取窗口【之前】的事件，不含当前批")
s = Session()
emp = s.query(EventRow.employee_id).first()
emp = emp[0] if emp else None
if emp:
    cutoff = s.query(EventRow).filter_by(employee_id=emp).order_by(EventRow.occurred_at.desc()).first().occurred_at
    before = s.query(EventRow).filter(EventRow.employee_id == emp, EventRow.occurred_at < cutoff).count()
    bl = profiles.baseline_for(s, emp, cutoff)
    total = s.query(EventRow).filter_by(employee_id=emp).count()
    s.close()
    print(f"  计算机 {emp}：总事件 {total}，取 cutoff={cutoff:%H:%M:%S}")
    print(f"  cutoff 之前事件 {before}，基线 sample_count={bl.get('sample_count')}")
    print(f"  => {'PASS 基线严格=窗口之前的历史(不含当前)' if bl.get('sample_count')==before else 'FAIL'}")
else:
    s.close(); print("  (无数据)")

print("\n================ UAT 结束 ================")
