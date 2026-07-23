"""快速测试本地 LLM：连通性 + 用「检测器风格」prompt 预览意图分析效果。

零依赖（仅用 stdlib urllib），密钥从同目录 .env 读取，不硬编码进源码。
"""
import json
import os
import urllib.request


def load_env(path: str) -> None:
    """极简 .env 加载器（避免引入 python-dotenv 依赖）。"""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            v = v.split("#", 1)[0].strip().strip('"').strip("'")
            os.environ.setdefault(k.strip(), v)


# 从脚本同目录读 .env
load_env(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

BASE = os.environ.get("LLM_BASE_URL", "http://10.4.128.18:4000/v1")
KEY = os.environ["LLM_API_KEY"]
MODEL = os.environ.get("LLM_MODEL", "Qwen3-32B")


def chat(messages, model=MODEL, temperature=0.1, max_tokens=400):
    body = json.dumps({
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE}/chat/completions",
        data=body,
        headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8"))


if __name__ == "__main__":
    # 用真实检测场景的 prompt，预览 AI 意图分析效果
    msgs = [
        {"role": "system", "content":
            "你是员工终端行为日志分析助手。根据给定行为序列，判断员工意图、对个人基线的偏离程度、"
            "并给出风险分(0-100)。只输出合法 JSON，不要多余解释。"
            "字段：intent(枚举: data_exfiltration|job_seeking|baseline_deviation|normal_work), "
            "deviation(none|minor|major|severe), risk_score(0-100), explanation(一句中文)。"},
        {"role": "user", "content":
            "行为序列（员工：zhangsan）：\n"
            "02:28 打开 客户名单_2026.xlsx\n"
            "02:29 U盘挂载\n"
            "02:30 一次性拷贝 200 个文件到 U盘\n"
            "基线：平时 9-18 点活跃、日均文档操作 15 次、从不使用 U盘、从不接触客户名单、从不深夜操作。"},
    ]
    print(f"模型: {MODEL}  @ {BASE}\n")
    r = chat(msgs)
    print("=== AI 回复 ===")
    print(r["choices"][0]["message"]["content"])
    u = r.get("usage", {})
    print(f"\n(tokens: prompt={u.get('prompt_tokens')}, completion={u.get('completion_tokens')})")
