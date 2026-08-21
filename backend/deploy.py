"""一键部署: 本地改动 → Babel预编译 → 服务器/容器 → 健康检查。

用法(本地仓库根目录):
    /d/PythonProject/python.exe backend/deploy.py          # 全量(后端py+前端)
    /d/PythonProject/python.exe backend/deploy.py --front  # 仅前端(不重启服务,不掉登录)

流程:
  1. py_compile 校验所有后端 .py
  2. node + libs/babel.js 预编译 index.html 的 JSX → 生成线上版(浏览器不再现场编译,首载快1-2s)
  3. sftp 上传 → docker cp 进容器 → 有 .py 改动时 docker restart
  4. 健康检查(页面200 + login 可达)
"""
import os
import re
import subprocess
import sys
import tempfile
import time

import paramiko

HOST, USER, PWD = "10.0.20.249", "root", "LX2320**"
HERE = os.path.dirname(os.path.abspath(__file__))
REMOTE = "/root/syslog/backend"
CONTAINER = "ipguard-ai"
PY_FILES = ["api.py", "db.py", "dicts.py", "detector.py", "llm_client.py", "pipeline.py", "profiles.py", "syslog_recv.py", "selfheal.py", "parser_ipg.py", "docscan.py", "massops.py", "storyline.py", "dayreview.py"]


def _node() -> str:
    """node 绝对路径(不依赖 PATH——宿主环境变量异常时 which 失效,2026-08-18 实测)。"""
    import shutil
    for p in (shutil.which("node"), r"C:\Program Files\nodejs\node.exe",
              r"C:\Program Files (x86)\nodejs\node.exe",
              os.path.expandvars(r"%LOCALAPPDATA%\Programs\nodejs\node.exe")):
        if p and os.path.exists(p):
            return p
    raise SystemExit("找不到 node.exe")


def sh(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", cwd=HERE)
    if r.returncode != 0:
        print(r.stdout, r.stderr)
        raise SystemExit(f"命令失败: {cmd}")
    return r.stdout


def ensure_babel() -> str:
    """本地缓存服务器同款 babel.js(与浏览器转译行为一致)。"""
    p = os.path.join(HERE, "libs", "babel.js")
    if not os.path.exists(p):
        os.makedirs(os.path.dirname(p), exist_ok=True)
        import urllib.request
        urllib.request.urlretrieve(f"http://{HOST}:18000/libs/babel.js", p)  # 不依赖PATH里的curl
        if not os.path.exists(p) or os.path.getsize(p) < 100000:
            raise SystemExit("下载 babel.js 失败")
    return p


def precompile_index() -> str:
    """返回预编译版 index.html(内联 babel script 替换为编译产物,并去掉 babel.js 引用)。"""
    import json
    html = open(os.path.join(HERE, "static", "index.html"), encoding="utf-8").read()
    m = re.search(r'<script type="text/babel">(.*?)</script>', html, re.S)
    if not m:
        raise SystemExit("未找到内联 text/babel script")
    with tempfile.NamedTemporaryFile("w", suffix=".jsx", delete=False, encoding="utf-8") as f:
        f.write(m.group(1))
        jsx = f.name
    babel_path = ensure_babel().replace("\\", "/")  # 正斜杠避免 JS 字符串转义地狱
    runner = (
        f"const b=require({json.dumps(babel_path)});const fs=require('fs');\n"
        "const src=fs.readFileSync(process.argv[2],'utf8');\n"  # argv[0]=node, argv[1]=本脚本
        "const out=b.transform(src,{presets:['react']}).code;\n"
        "fs.writeFileSync(process.argv[3],out);\n"
    )
    with tempfile.NamedTemporaryFile("w", suffix=".cjs", delete=False, encoding="utf-8") as f:
        f.write(runner)
        runner_js = f.name
    out_js = jsx + ".js"
    sh(f'"{_node()}" "{runner_js}" "{jsx}" "{out_js}"')
    compiled = open(out_js, encoding="utf-8").read().replace("</script", "<\\/script")
    for p in (jsx, out_js, runner_js):
        os.unlink(p)
    html = html.replace('<script src="/libs/babel.js"></script>\n', "")
    return html.replace(m.group(0), "<script>\n" + compiled + "\n</script>")


def main():
    only_front = "--front" in sys.argv
    files = [f for f in PY_FILES if not only_front]

    for f in files:
        subprocess.run([sys.executable, "-m", "py_compile", os.path.join(HERE, f)], check=True)
    print("PY OK" if files else "(仅前端)")

    dist_html = precompile_index()
    print("BABEL 预编译 OK, 线上包 %.1f KB" % (len(dist_html.encode("utf-8")) / 1024))

    t = paramiko.Transport((HOST, 22))
    t.connect(username=USER, password=PWD)
    sftp = paramiko.SFTPClient.from_transport(t)
    cli = paramiko.SSHClient()
    cli._transport = t

    def run(cmd, timeout=300):
        _, o, e = cli.exec_command(cmd, timeout=timeout)
        out, err = o.read().decode()[:500], e.read().decode()[:300]
        print(f"$ {cmd}\n{out}{err and '[STDERR] ' + err}")

    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False, encoding="utf-8") as f:
        f.write(dist_html)
        dist_file = f.name
    sftp.put(dist_file, REMOTE + "/static/index.html")
    os.unlink(dist_file)
    print("uploaded index.html(预编译版)")
    for extra in ("favicon.png", "logo.png"):  # 静态资源(存在才传)
        p = os.path.join(HERE, "static", extra)
        if os.path.exists(p):
            sftp.put(p, REMOTE + "/static/" + extra)
            print("uploaded", extra)
    for f in files:
        sftp.put(os.path.join(HERE, f), REMOTE + "/" + f)
        print("uploaded", f)
    sftp.close()

    run(f"docker cp {REMOTE}/static/index.html {CONTAINER}:/app/static/index.html")
    for extra in ("favicon.png", "logo.png"):
        if os.path.exists(os.path.join(HERE, "static", extra)):
            run(f"docker cp {REMOTE}/static/{extra} {CONTAINER}:/app/static/{extra}")
    for f in files:
        run(f"docker cp {REMOTE}/{f} {CONTAINER}:/app/{f}")
    if files:
        run(f"docker exec {CONTAINER} sh -c 'rm -rf /app/__pycache__'")  # 陈旧pyc曾致新代码不生效(2026-08-20巡检)
        run(f"docker restart {CONTAINER}")
        time.sleep(10)
    run("curl -s -o /dev/null -w 'page:%{http_code}' http://localhost:18000/index.html && "
        "curl -s -o /dev/null -w ' api:%{http_code}(401=可达)' http://localhost:18000/api/me")
    t.close()
    print("=== 部署完成 ===")


if __name__ == "__main__":
    main()
