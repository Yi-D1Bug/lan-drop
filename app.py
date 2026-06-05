#!/usr/bin/env python3
"""局域网文件传输工具 — 启动后局域网内任意设备用浏览器访问即可上传/下载文件。"""
import io
import os
import socket
import argparse
from datetime import datetime
from pathlib import Path

from flask import (
    Flask,
    request,
    jsonify,
    send_from_directory,
    abort,
    render_template_string,
)
from werkzeug.utils import secure_filename

__version__ = "1.0.0"

SHARE_DIR = Path(os.environ.get("LAN_SHARE_DIR", "shared")).resolve()
SHARE_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = None  # 不限制单次上传大小


def safe_target(filename: str) -> Path:
    """把用户提供的文件名解析成 SHARE_DIR 内的安全路径,阻止路径穿越。"""
    name = secure_filename(filename)
    if not name:
        abort(400, "非法文件名")
    target = (SHARE_DIR / name).resolve()
    # 确保最终路径仍在共享目录内
    if SHARE_DIR not in target.parents and target != SHARE_DIR:
        abort(400, "非法路径")
    return target


def unique_target(filename: str) -> Path:
    """同名文件自动加序号,避免覆盖已有文件。"""
    target = safe_target(filename)
    if not target.exists():
        return target
    stem, suffix = target.stem, target.suffix
    i = 1
    while True:
        candidate = safe_target(f"{stem}({i}){suffix}")
        if not candidate.exists():
            return candidate
        i += 1


def human_size(num: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num < 1024:
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} PB"


PLACEHOLDER_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>局域网文件传输</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif;
         background: #f4f5f7; color: #222; padding: 16px; }
  .wrap { max-width: 760px; margin: 0 auto; }
  h1 { font-size: 20px; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
  h1 .ver { font-size: 12px; font-weight: normal; color: #9ca3af; }
  .drop { border: 2px dashed #b9c0cc; border-radius: 12px; background: #fff;
          padding: 36px 16px; text-align: center; cursor: pointer; transition: .15s; }
  .drop.over { border-color: #3b82f6; background: #eff6ff; }
  .drop p { color: #6b7280; font-size: 14px; }
  .drop strong { color: #3b82f6; }
  #bars { margin: 12px 0; }
  .bar { background: #fff; border-radius: 8px; padding: 8px 12px; margin-bottom: 8px;
         font-size: 13px; box-shadow: 0 1px 2px rgba(0,0,0,.05); }
  .bar .track { height: 6px; background: #e5e7eb; border-radius: 3px; margin-top: 6px; overflow: hidden; }
  .bar .fill { height: 100%; width: 0; background: #3b82f6; transition: width .2s; }
  .list { background: #fff; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,.06); overflow: hidden; }
  .row { display: flex; align-items: center; padding: 12px 16px; border-bottom: 1px solid #f0f1f3; gap: 12px; }
  .row:last-child { border-bottom: none; }
  .row .name { flex: 1; font-size: 14px; word-break: break-all; }
  .row .meta { font-size: 12px; color: #9ca3af; white-space: nowrap; }
  .row a, .row button { font-size: 13px; text-decoration: none; border: none;
         background: none; cursor: pointer; padding: 4px 8px; border-radius: 6px; }
  .row a { color: #3b82f6; }
  .row a:hover { background: #eff6ff; }
  .row .del { color: #ef4444; }
  .row .del:hover { background: #fef2f2; }
  .empty { padding: 40px; text-align: center; color: #9ca3af; font-size: 14px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>📁 局域网文件传输 <span class="ver">v{{ version }}</span></h1>
  <div class="drop" id="drop">
    <p><strong>点击选择</strong> 或拖拽文件到此处上传</p>
    <p style="margin-top:6px;font-size:12px;">局域网内任意设备均可下载</p>
  </div>
  <input type="file" id="picker" multiple hidden>
  <div id="bars"></div>
  <div class="list" id="list"><div class="empty">加载中…</div></div>
</div>
<script>
const drop = document.getElementById('drop');
const picker = document.getElementById('picker');
const bars = document.getElementById('bars');
const list = document.getElementById('list');

drop.onclick = () => picker.click();
picker.onchange = () => { uploadFiles(picker.files); picker.value = ''; };
['dragover','dragenter'].forEach(e =>
  drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.add('over'); }));
['dragleave','drop'].forEach(e =>
  drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.remove('over'); }));
drop.addEventListener('drop', ev => uploadFiles(ev.dataTransfer.files));

function uploadFiles(files) {
  if (!files || !files.length) return;
  const fd = new FormData();
  for (const f of files) fd.append('files', f);
  const total = [...files].map(f => f.name).join(', ');

  const bar = document.createElement('div');
  bar.className = 'bar';
  bar.innerHTML = `<div>⬆️ ${total}</div><div class="track"><div class="fill"></div></div>`;
  bars.appendChild(bar);
  const fill = bar.querySelector('.fill');

  const xhr = new XMLHttpRequest();
  xhr.open('POST', '/api/upload');
  xhr.upload.onprogress = e => {
    if (e.lengthComputable) fill.style.width = (e.loaded / e.total * 100) + '%';
  };
  xhr.onload = () => {
    fill.style.width = '100%';
    setTimeout(() => bar.remove(), 800);
    loadFiles();
  };
  xhr.onerror = () => { bar.querySelector('div').textContent = '❌ 上传失败: ' + total; };
  xhr.send(fd);
}

async function loadFiles() {
  const res = await fetch('/api/files');
  const files = await res.json();
  if (!files.length) { list.innerHTML = '<div class="empty">暂无文件,上传一个试试</div>'; return; }
  list.innerHTML = files.map(f => `
    <div class="row">
      <span class="name">${escapeHtml(f.name)}</span>
      <span class="meta">${f.size_h} · ${f.mtime}</span>
      <a href="/download/${encodeURIComponent(f.name)}">下载</a>
      <button class="del" onclick="del('${encodeURIComponent(f.name)}')">删除</button>
    </div>`).join('');
}

async function del(name) {
  if (!confirm('确定删除该文件?')) return;
  await fetch('/api/delete/' + name, { method: 'POST' });
  loadFiles();
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, c =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

loadFiles();
setInterval(loadFiles, 4000);
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(PLACEHOLDER_HTML, version=__version__)


@app.route("/api/files")
def list_files():
    files = []
    for p in SHARE_DIR.iterdir():
        if p.is_file():
            stat = p.stat()
            files.append(
                {
                    "name": p.name,
                    "size": stat.st_size,
                    "size_h": human_size(stat.st_size),
                    "mtime": datetime.fromtimestamp(stat.st_mtime).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                }
            )
    files.sort(key=lambda f: f["mtime"], reverse=True)
    return jsonify(files)


@app.route("/api/upload", methods=["POST"])
def upload():
    uploaded = request.files.getlist("files")
    if not uploaded:
        return jsonify({"error": "没有文件"}), 400
    saved = []
    for f in uploaded:
        if not f.filename:
            continue
        target = unique_target(f.filename)
        f.save(target)
        saved.append(target.name)
    return jsonify({"saved": saved})


@app.route("/download/<path:filename>")
def download(filename):
    target = safe_target(filename)
    if not target.is_file():
        abort(404)
    return send_from_directory(SHARE_DIR, target.name, as_attachment=True)


@app.route("/api/delete/<path:filename>", methods=["POST"])
def delete(filename):
    target = safe_target(filename)
    if not target.is_file():
        abort(404)
    target.unlink()
    return jsonify({"deleted": target.name})


def get_lan_ip() -> str:
    """获取本机在局域网中的 IP。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def print_banner(ip: str, port: int):
    url = f"http://{ip}:{port}"
    print("\n" + "=" * 48)
    print(f"  局域网文件传输 v{__version__} 已启动")
    print(f"  共享目录: {SHARE_DIR}")
    print(f"  本机访问: http://127.0.0.1:{port}")
    print(f"  局域网访问: {url}")
    print("=" * 48)
    try:
        import qrcode

        qr = qrcode.QRCode(border=1)
        qr.add_data(url)
        qr.make(fit=True)
        qr.print_ascii(out=io.StringIO())  # 触发计算
        print("  手机扫码访问:")
        qr.print_ascii(invert=True)
    except Exception:
        print("  (安装 qrcode 可显示二维码: pip install qrcode)")
    print("  按 Ctrl+C 停止\n")


def main():
    parser = argparse.ArgumentParser(description="局域网文件传输工具")
    parser.add_argument("--port", type=int, default=8000, help="监听端口 (默认 8000)")
    parser.add_argument("--host", default="0.0.0.0", help="监听地址 (默认 0.0.0.0)")
    args = parser.parse_args()

    ip = get_lan_ip()
    print_banner(ip, args.port)
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
