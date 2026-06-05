#!/usr/bin/env python3
"""局域网文件传输工具 — 启动后局域网内任意设备用浏览器访问即可上传/下载文件。"""
import io
import os
import socket
import argparse
import threading
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

__version__ = "1.1.0"

SHARE_DIR = Path(os.environ.get("LAN_SHARE_DIR", "shared")).resolve()
SHARE_DIR.mkdir(parents=True, exist_ok=True)

# 共享文本消息(内存存储,服务重启后清空)
MAX_MESSAGES = 200
_messages = []
_messages_lock = threading.Lock()
_msg_seq = 0

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
  h2 { font-size: 15px; margin: 24px 0 10px; color: #374151; }
  .composer { background: #fff; border-radius: 12px; padding: 12px; box-shadow: 0 1px 3px rgba(0,0,0,.06); }
  .composer textarea { width: 100%; border: 1px solid #e5e7eb; border-radius: 8px;
         padding: 10px; font-size: 14px; resize: vertical; min-height: 64px;
         font-family: inherit; }
  .composer textarea:focus { outline: none; border-color: #3b82f6; }
  .composer .send { margin-top: 8px; float: right; background: #3b82f6; color: #fff;
         border: none; border-radius: 8px; padding: 8px 20px; font-size: 14px; cursor: pointer; }
  .composer .send:hover { background: #2563eb; }
  .composer::after { content: ""; display: block; clear: both; }
  .msgs { margin-top: 12px; }
  .msg { background: #fff; border-radius: 10px; padding: 10px 14px; margin-bottom: 8px;
         box-shadow: 0 1px 2px rgba(0,0,0,.05); }
  .msg .head { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
  .msg .from { font-size: 12px; color: #9ca3af; flex: 1; }
  .msg .text { font-size: 14px; white-space: pre-wrap; word-break: break-all; line-height: 1.5; }
  .msg button { font-size: 12px; border: none; background: none; cursor: pointer;
         padding: 3px 8px; border-radius: 6px; }
  .msg .copy { color: #3b82f6; }
  .msg .copy:hover { background: #eff6ff; }
  .msg .delm { color: #ef4444; }
  .msg .delm:hover { background: #fef2f2; }
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

  <h2>📋 文本互传</h2>
  <div class="composer">
    <textarea id="msgInput" placeholder="输入要分享的文本、链接、验证码…&#10;Ctrl+Enter 发送"></textarea>
    <button class="send" id="msgSend">发送</button>
  </div>
  <div class="msgs" id="msgs"></div>
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

// ---- 文本互传 ----
const msgInput = document.getElementById('msgInput');
const msgSend = document.getElementById('msgSend');
const msgs = document.getElementById('msgs');

msgSend.onclick = sendMessage;
msgInput.addEventListener('keydown', e => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); sendMessage(); }
});

async function sendMessage() {
  const text = msgInput.value.trim();
  if (!text) return;
  msgSend.disabled = true;
  try {
    const res = await fetch('/api/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text })
    });
    if (res.ok) { msgInput.value = ''; loadMessages(); }
    else { const e = await res.json(); alert(e.error || '发送失败'); }
  } finally { msgSend.disabled = false; }
}

async function loadMessages() {
  const res = await fetch('/api/messages');
  const items = await res.json();
  if (!items.length) { msgs.innerHTML = ''; return; }
  msgs.innerHTML = items.map(m => `
    <div class="msg">
      <div class="head">
        <span class="from">${escapeHtml(m.ip)} · ${m.time}</span>
        <button class="copy" data-id="${m.id}">复制</button>
        <button class="delm" data-id="${m.id}">删除</button>
      </div>
      <div class="text" id="msgtext-${m.id}">${escapeHtml(m.text)}</div>
    </div>`).join('');
}

msgs.addEventListener('click', e => {
  const id = e.target.dataset.id;
  if (!id) return;
  if (e.target.classList.contains('copy')) copyMessage(id, e.target);
  else if (e.target.classList.contains('delm')) deleteMessage(id);
});

async function copyMessage(id, btn) {
  const text = document.getElementById('msgtext-' + id).textContent;
  try {
    await navigator.clipboard.writeText(text);
    const old = btn.textContent; btn.textContent = '已复制';
    setTimeout(() => btn.textContent = old, 1200);
  } catch {
    // 非 HTTPS 下 clipboard API 不可用,降级用选区复制
    const r = document.createRange();
    r.selectNode(document.getElementById('msgtext-' + id));
    const sel = getSelection(); sel.removeAllRanges(); sel.addRange(r);
    try { document.execCommand('copy'); } catch {}
    sel.removeAllRanges();
    const old = btn.textContent; btn.textContent = '已复制';
    setTimeout(() => btn.textContent = old, 1200);
  }
}

async function deleteMessage(id) {
  await fetch('/api/messages/' + id, { method: 'DELETE' });
  loadMessages();
}

loadFiles();
loadMessages();
setInterval(loadFiles, 4000);
setInterval(loadMessages, 4000);
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


@app.route("/api/messages")
def list_messages():
    with _messages_lock:
        return jsonify(list(_messages))


@app.route("/api/messages", methods=["POST"])
def post_message():
    global _msg_seq
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "内容为空"}), 400
    if len(text) > 10000:
        return jsonify({"error": "内容过长(上限 10000 字符)"}), 400
    with _messages_lock:
        _msg_seq += 1
        msg = {
            "id": _msg_seq,
            "text": text,
            "ip": request.remote_addr or "?",
            "time": datetime.now().strftime("%H:%M:%S"),
        }
        _messages.insert(0, msg)
        del _messages[MAX_MESSAGES:]
    return jsonify(msg)


@app.route("/api/messages/<int:msg_id>", methods=["DELETE"])
def delete_message(msg_id):
    with _messages_lock:
        before = len(_messages)
        _messages[:] = [m for m in _messages if m["id"] != msg_id]
        deleted = before != len(_messages)
    if not deleted:
        abort(404)
    return jsonify({"deleted": msg_id})


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
