"""本地 LLM 客户端（OpenAI 兼容，默认 Qwen3-32B via LiteLLM 代理）。

密钥从同目录 .env 读取，绝不硬编码进源码。
"""
import json
import os
import re
import urllib.request

import dicts


def load_env(path: str) -> None:
    """极简 .env 加载器（免引入 python-dotenv）。"""
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


load_env(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

BASE = os.environ.get("LLM_BASE_URL", "http://10.4.128.18:4000/v1").rstrip("/")
KEY = os.environ.get("LLM_API_KEY", "")
MODEL = os.environ.get("LLM_MODEL", "Qwen3-32B")


def _candidates():
    """返回 [(base, key, model)...]：活动模型优先，另一个作兜底。配置来自 DB>.env>默认。
    DeepSeek 需要单独的 base_url（若配置了），否则用默认 Qwen 地址。"""
    # 主地址（Qwen）
    main_base = (dicts.get_setting("llm_base_url") or os.environ.get("LLM_BASE_URL")
                 or "http://10.4.128.18:4000/v1").rstrip("/")
    active = (dicts.get_setting("llm_active") or "qwen").lower()
    qwen_key = dicts.get_setting("llm_qwen_key") or os.environ.get("LLM_QWEN_KEY") \
        or os.environ.get("LLM_API_KEY") or ""
    qwen_model = dicts.get_setting("llm_qwen_model") or os.environ.get("LLM_QWEN_MODEL") or "Qwen3-32B"
    ds_key = dicts.get_setting("llm_deepseek_key") or os.environ.get("LLM_DEEPSEEK_KEY") or ""
    ds_model = dicts.get_setting("llm_deepseek_model") or os.environ.get("LLM_DEEPSEEK_MODEL") or "deepseek"
    ds_base = (dicts.get_setting("llm_deepseek_base_url") or os.environ.get("LLM_DEEPSEEK_BASE_URL")
               or main_base).rstrip("/")
    pairs = {
        "qwen": (main_base, qwen_key, qwen_model),
        "deepseek": (ds_base, ds_key, ds_model),
    }
    order = [active] + [m for m in ("qwen", "deepseek") if m != active]
    # 只要 base_url 有效就返回（本地模型可能无需 key）
    return [(pairs[m][0], pairs[m][1], pairs[m][2]) for m in order if pairs[m][0] and pairs[m][0].startswith("http")]


def chat(messages, model=None, temperature=0.1, max_tokens=1000, timeout=120):
    """调用 /chat/completions。活动模型优先，失败自动切换另一个兜底；都失败才抛异常。"""
    base_body = {"messages": messages, "temperature": temperature, "max_tokens": max_tokens}
    last_err = None
    for base, key, mdl in _candidates():
        try:
            body = json.dumps({**base_body, "model": model or mdl}).encode("utf-8")
            req = urllib.request.Request(
                f"{base}/chat/completions", data=body,
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                method="POST")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"]
        except Exception as e:
            last_err = e
            continue
    raise RuntimeError(f"所有模型均调用失败: {last_err}")


def extract_json(text: str) -> dict:
    """鲁棒地从模型输出提取 JSON：去 <think> 块、去 ```fences、截取大括号段；失败则正则兜底。"""
    if not text:
        return {}
    t = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)   # 去 Qwen3 思考块
    t = re.sub(r"```(?:json)?\s*", "", t).replace("```", "")
    s, e = t.find("{"), t.rfind("}")
    if s != -1 and e != -1 and e > s:
        try:
            return json.loads(t[s:e + 1])
        except json.JSONDecodeError:
            pass
    out: dict = {}
    for key, pat in [("intent", r'"intent"\s*:\s*"([^"]+)"'),
                     ("deviation", r'"deviation"\s*:\s*"([^"]+)"'),
                     ("explanation", r'"explanation"\s*:\s*"([^"]+)"')]:
        m = re.search(pat, t)
        if m:
            out[key] = m.group(1)
    m = re.search(r'"risk_score"\s*:\s*(\d+)', t)
    if m:
        out["risk_score"] = int(m.group(1))
    return out


if __name__ == "__main__":
    print("模型:", MODEL, " @ ", BASE)
    print(chat([{"role": "user", "content": "用一句中文自我介绍。"}], max_tokens=80))
