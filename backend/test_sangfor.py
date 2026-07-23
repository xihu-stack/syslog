"""测试深信服解析 + 降噪聚合：看几万条/天会被压缩成多少。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parser_sangfor import parse_sangfor
from web_aggregator import aggregate, is_noise

PATH = r"D:\代码\日志平台\samples\sangfor_sample.csv"
events = parse_sangfor(PATH)
print(f"原始解析: {len(events)} 条 WEB 事件\n原始明细:")
for e in events:
    noise = "  [噪声-过滤]" if is_noise((e.raw or {}).get("domain", ""), e.target_value) else ""
    print(f"  {e.employee_id:<12} 分类={e.raw.get('category'):<5} {e.raw.get('domain')}{noise}")

agg = aggregate(events)
rate = int((1 - len(agg) / max(len(events), 1)) * 100)
print(f"\n降噪+聚合后: {len(agg)} 条（原始 {len(events)} → 压缩 {rate}%）")
for e in agg:
    print(f"  {e.employee_id:<12} 分类={e.raw.get('category'):<5} {e.target_value}  ×{e.count}")
