"""端到端跑一遍（CLI）：解析 Excel → 检测 → 打印每个窗口的 AI 判断与告警。

用法: python run_detect.py [xlsx路径]
不传路径默认解析桌面 111.xlsx。
"""
import sys

from parser_ipguard import parse_ipguard_excel
from detector import detect

PATH = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\huxi\Desktop\111.xlsx"


def main():
    events = parse_ipguard_excel(PATH)
    print(f"解析到 {len(events)} 条事件，开始 AI 检测（调用本地 Qwen3-32B）...\n")
    verdicts, alerts = detect(events, risk_threshold=50)

    print(f"===== 触发分析 {len(verdicts)} 个行为窗口 =====\n")
    for it in verdicts:
        v = it["verdict"]
        mark = "[告警]" if v.get("risk_score", 0) >= 50 else "      "
        ai = "" if v.get("ai_participated", True) else "  (规则兜底)"
        print(f"{mark} [{it['window_start']:%m-%d %H:%M}] {it['employee']:<14}"
              f" 风险={v.get('risk_score', 0):<3} 意图={v.get('intent'):<20}{ai}")
        print(f"          {v.get('explanation','')}\n")

    print(f"===== 生成 {len(alerts)} 条告警（风险>=50）=====")
    for a in alerts:
        v = a["verdict"]
        print(f"  >>> {a['employee']}  风险{v.get('risk_score')}  {v.get('explanation')}")


if __name__ == "__main__":
    main()
