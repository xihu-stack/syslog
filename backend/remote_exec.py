"""临时辅助: paramiko 执行远程 docker 命令, 输出到本地文件"""
import sys, paramiko

HOST, USER, PWD = "10.0.20.249", "root", "LX2320**"

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
