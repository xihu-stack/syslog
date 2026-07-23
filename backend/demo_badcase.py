"""合成高危场景：验证告警路径（证明系统能抓到真实风险）。

注意：这是测试用例，不是你的真实日志。你的 111.xlsx 全是良性操作，0 告警是正确的；
这里故意造一条"凌晨拷客户名单到U盘"来证明告警路径通畅。
"""
from datetime import datetime

from models import CanonicalEvent, Category
from detector import detect

events = [
    CanonicalEvent(datetime(2026, 7, 22, 2, 28), "zhangsan", "PC-001",
                   Category.DOC.value, "READ", "FILE", "客户名单_2026.xlsx", 204800,
                   raw={"channel": "LOCAL", "application": "EXCEL.EXE"}),
    CanonicalEvent(datetime(2026, 7, 22, 2, 29), "zhangsan", "PC-001",
                   Category.DOC.value, "MOUNT", "DEVICE", "USB_Kingston", 0,
                   raw={"channel": "USB", "application": "Explorer.EXE"}),
    CanonicalEvent(datetime(2026, 7, 22, 2, 30), "zhangsan", "PC-001",
                   Category.DOC.value, "COPY", "FILE", "客户名单_2026.xlsx", 20480000, 200,
                   raw={"channel": "USB", "application": "Explorer.EXE"}),
]

verdicts, alerts = detect(events, risk_threshold=50)
for it in verdicts:
    v = it["verdict"]
    print(f"[{it['window_start']:%m-%d %H:%M}] {it['employee']}  风险={v.get('risk_score')}  "
          f"意图={v.get('intent')}  偏离={v.get('deviation')}")
    print("   解释:", v.get("explanation"))
    print("   通道:", v.get("channels"))
print(f"\n>>> 生成告警 {len(alerts)} 条（风险>=50）")
