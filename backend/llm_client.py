"""本地 LLM 客户端（OpenAI 兼容，默认 Qwen3-32B via LiteLLM 代理）。

密钥从同目录 .env 读取，绝不硬编码进源码。
"""
import json
import os
import re
import time
import urllib.error
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
    _ds_cfg = [dicts.get_setting(k) or "" for k in ("llm_deepseek_key", "llm_deepseek_model",
                                                    "llm_deepseek_base_url")]
    ds_key = _ds_cfg[0] or os.environ.get("LLM_DEEPSEEK_KEY") or ""
    ds_model = _ds_cfg[1] or os.environ.get("LLM_DEEPSEEK_MODEL") or "deepseek"
    ds_base = (_ds_cfg[2] or os.environ.get("LLM_DEEPSEEK_BASE_URL") or main_base).rstrip("/")
    pairs = {
        "qwen": (main_base, qwen_key, qwen_model),
        "deepseek": (ds_base, ds_key, ds_model),
    }
    order = [active] + [m for m in ("qwen", "deepseek") if m != active]
    # 只要 base_url 有效就返回（本地模型可能无需 key）。
    # 兜底槽三项(DB+env)均未显式配置=槽位空(单模型模式,如DeepSeek暂下线):
    # 不进候选队列,主力失败也不浪费一次注定401的尝试;填回任一项即自动恢复
    _ds_empty = not any(_ds_cfg) and not any(k in os.environ for k in
                                            ("LLM_DEEPSEEK_KEY", "LLM_DEEPSEEK_MODEL", "LLM_DEEPSEEK_BASE_URL"))
    _skip = {"deepseek"} if _ds_empty else set()
    return [(pairs[m][0], pairs[m][1], pairs[m][2]) for m in order
            if m not in _skip and pairs[m][0] and pairs[m][0].startswith("http")]


LAST_MODEL = ""  # 最近一次成功调用实际使用的模型(研判落库时读,替代硬编码)

# LLM 调用统计(进程内存级,重启清零): 供系统健康页展示 AI 性能
_STATS = {"total": 0, "fail": 0, "ms": 0, "last_ms": 0, "by_model": {}}


def stats() -> dict:
    n = _STATS["total"] - _STATS["fail"]
    return {**_STATS, "avg_ms": round(_STATS["ms"] / n) if n > 0 else 0,
            "by_model": {k: {**v, "avg_ms": round(v["ms"] / v["calls"]) if v["calls"] else 0}
                         for k, v in _STATS["by_model"].items()}}


def smart_model():
    """理解型任务的深度模型(总结/规则扫描/告警复核),空=用活动模型。
    三模型分工(2026-08-18实测): Qwen=高频研判+问答(快/格式稳) / DeepSeek-R1(本地)=深度理解(思考长)。
    glm-5为外部转发,数据出境红线禁用。"""
    try:
        return dicts.get_setting("llm_smart_model") or None
    except Exception:
        return None


def strip_think(text: str) -> str:
    """剥离推理模型的思考块。兼容三种形态:
    1) 标准 <think>...</think>;2) 本地R1部署的parser半残:content缺开标签只有</think>
    (闭合标签前全是思考,之后是正文);3) 无思考块原样返回。"""
    t = re.sub(r"<think>.*?</think>", "", text or "", flags=re.S)
    if "</think>" in t and "<think>" not in t:
        t = t.split("</think>", 1)[1]
    return t


def chat(messages, model=None, temperature=0.1, max_tokens=1000, timeout=180):
    """调用 /chat/completions。活动模型优先，失败自动切换另一个兜底；都失败才抛异常。
    model=指定深度模型(如 glm-5)时:指定模型优先,全失败(如限流429)自动回退活动模型,保可用性。
    2026-09-01: llm_enabled=0(本地AI暂停)快速失败——防各AI功能(日复核/周报/
    摸鱼总结等)对着已关停的本地模型空等180s超时;调用方均有except兜底路径。"""
    global LAST_MODEL
    if (dicts.get_setting("llm_enabled") or "1") == "0":
        raise RuntimeError("AI已暂停(llm_enabled=0)")
    base_body = {"messages": messages, "temperature": temperature, "max_tokens": max_tokens}
    cands = _candidates()
    attempts = [(base, key, (model or mdl)) for base, key, mdl in cands]
    if model:
        attempts += [(base, key, mdl) for base, key, mdl in cands]  # 回退:不指定模型再试一轮
    last_err = None
    for base, key, mdl in attempts:
        _retry_429 = 2  # 上游限流(glm-5"访问量过大")通常几秒即恢复:退避重试再回退
        _t0 = time.time()
        while True:
            try:
                _payload = {**base_body, "model": mdl}
                if "qwen" in mdl.lower():
                    # Qwen3系默认开思考:思维链直接写进content,800-1000 token预算被
                    # 推理耗尽,JSON永远出不来(2026-08-28 Qwen3.8-27B上线首验:
                    # 17/17 verdict unknown/0,全是"我们需要回答用户…"开头无JSON)
                    _payload["chat_template_kwargs"] = {"enable_thinking": False}
                body = json.dumps(_payload).encode("utf-8")
                req = urllib.request.Request(
                    f"{base}/chat/completions", data=body,
                    headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                    method="POST")
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                content = data["choices"][0]["message"].get("content") or ""
                if not content.strip():
                    # 深度模型偶发空输出(思考耗尽token/网关并发拥塞截断)——视为失败走回退,
                    # 否则上层拿到空串会把调用当成功(2026-08-18 摸鱼总结空结果排查结论)
                    last_err = RuntimeError(f"{mdl} 返回空内容(疑似思考token耗尽或网关拥塞)")
                    print(f"[llm] {mdl} 空内容(耗时{round((time.time()-_t0)*1000)}ms)", flush=True)
                    break
                LAST_MODEL = mdl  # 记录实际命中模型(可能是兜底切换后的)
                _dt = round((time.time() - _t0) * 1000)
                _STATS["total"] += 1; _STATS["ms"] += _dt; _STATS["last_ms"] = _dt
                _m = _STATS["by_model"].setdefault(mdl, {"calls": 0, "ms": 0, "fails": 0})
                _m["calls"] += 1; _m["ms"] += _dt
                return content
            except urllib.error.HTTPError as e:
                if e.code == 429 and _retry_429 > 0:
                    _retry_429 -= 1
                    time.sleep(3)
                    continue
                last_err = e
                # 失败必须落日志(2026-08-28全量重判审计:15窗口超时走兜底,
                # docker logs里grep不到任何痕迹,兜底告警混进AI研判无据可查)
                print(f"[llm] {mdl} HTTP{e.code}: {str(e)[:120]}", flush=True)
                _STATS["fail"] += 1
                _STATS["by_model"].setdefault(mdl, {"calls": 0, "ms": 0, "fails": 0})["fails"] += 1
                break
            except Exception as e:
                last_err = e
                print(f"[llm] {mdl} {type(e).__name__}: {str(e)[:120]}", flush=True)
                _STATS["fail"] += 1
                _STATS["by_model"].setdefault(mdl, {"calls": 0, "ms": 0, "fails": 0})["fails"] += 1
                break
    raise RuntimeError(f"所有模型均调用失败: {last_err}")


def extract_json(text: str) -> dict:
    """鲁棒地从模型输出提取 JSON：去思考块、去 ```fences、截取大括号段；失败则正则兜底。"""
    if not text:
        return {}
    t = strip_think(text)
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
                     ("explanation", r'"explanation"\s*:\s*"([^"]+)"'),
                     ("channels", r'"channels"\s*:\s*\[([^\]]+)\]')]:
        m = re.search(pat, t)
        if m:
            if key == "channels":
                out[key] = [x.strip().strip('"').strip("'") for x in m.group(1).split(",") if x.strip()]
            else:
                out[key] = m.group(1)
    m = re.search(r'"risk_score"\s*:\s*(\d+)', t)
    if m:
        out["risk_score"] = int(m.group(1))
    return out


if __name__ == "__main__":
    print("模型:", MODEL, " @ ", BASE)
    print(chat([{"role": "user", "content": "用一句中文自我介绍。"}], max_tokens=80))
