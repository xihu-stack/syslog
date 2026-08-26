"""临时辅助: paramiko 执行远程 docker 命令, 输出到本地文件"""
import sys, paramiko

try:
    from _deploy_secret import HOST, USER, PWD  # 凭据不进git(2026-08-26)
except ImportError:
    import os
    HOST = os.environ.get("DEPLOY_HOST", "10.0.20.249")
    USER = os.environ.get("DEPLOY_USER", "root")
    PWD = os.environ.get("DEPLOY_PWD", "")

def run(cmd: str, out_path: str):
    t = paramiko.Transport((HOST, 22))
    t.connect(username=USER, password=PWD)
    ch = t.open_session()
    ch.exec_command(cmd)
    buf = b""
    while True:
        d = ch.recv(65536)
        if not d:
            break
        buf += d
    ch.close(); t.close()
    with open(out_path, "wb") as f:
        f.write(buf)
    print(f"exit={ch.exit_status} bytes={len(buf)} -> {out_path}")

if __name__ == "__main__":
    run(sys.argv[1], sys.argv[2])
