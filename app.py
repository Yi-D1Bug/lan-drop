#!/usr/bin/env python3
"""局域网文件传输工具 — 启动后局域网内任意设备用浏览器访问即可上传/下载文件。"""
import io
import json
import os
import re
import queue
import socket
import argparse
import threading
import unicodedata
from datetime import datetime
from pathlib import Path

from flask import (
    Flask,
    Response,
    request,
    jsonify,
    send_from_directory,
    abort,
    render_template_string,
    stream_with_context,
)

__version__ = "1.2.0"

SHARE_DIR = Path(os.environ.get("LAN_SHARE_DIR", "shared")).resolve()
SHARE_DIR.mkdir(parents=True, exist_ok=True)

# 共享文本消息(内存存储,服务重启后清空)
MAX_MESSAGES = 200
_messages = []
_messages_lock = threading.Lock()
_msg_seq = 0

# SSE 客户端管理
_sse_clients = []
_sse_clients_lock = threading.Lock()


def _broadcast(event: str, data: dict):
    """向所有 SSE 客户端广播一条事件。"""
    payload = f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
    dead = []
    with _sse_clients_lock:
        for q in _sse_clients:
            try:
                q.put_nowait(payload)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_clients.remove(q)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = None  # 不限制单次上传大小


# Windows 保留设备名,避免生成无法访问的文件
_WIN_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
# 文件名中需要剔除的字符:路径分隔符、控制字符及各系统非法字符
_BAD_CHARS = re.compile(r'[\x00-\x1f<>:"/\\|?*]')


def sanitize_filename(filename: str) -> str:
    """清洗用户提供的文件名:保留中文等 Unicode,去掉路径分隔符与非法字符。

    werkzeug 的 secure_filename 会丢弃所有非 ASCII 字符(中文名会变成只剩扩展名),
    因此这里改用自定义清洗,既保留可读名又防止路径穿越。
    """
    # 只取最后一段,丢弃任何目录部分(防穿越)
    name = filename.replace("\\", "/").split("/")[-1]
    name = unicodedata.normalize("NFC", name)
    name = _BAD_CHARS.sub("", name)
    name = name.strip().strip(".")  # 去掉首尾空格和点(Windows 不允许结尾点/空格)
    if name in (".", ".."):
        return ""
    if name.split(".")[0].upper() in _WIN_RESERVED:
        name = "_" + name
    return name[:255]  # 多数文件系统单段上限 255 字节,简单按字符截断


def safe_target(filename: str) -> Path:
    """把用户提供的文件名解析成 SHARE_DIR 内的安全路径,阻止路径穿越。"""
    name = sanitize_filename(filename)
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
  .nick-bar { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; font-size: 13px; color: #6b7280; }
  .nick-bar input { border: 1px solid #e5e7eb; border-radius: 6px; padding: 4px 8px;
         font-size: 13px; width: 100px; font-family: inherit; }
  .nick-bar input:focus { outline: none; border-color: #3b82f6; }
  .composer { background: #fff; border-radius: 12px; padding: 12px; box-shadow: 0 1px 3px rgba(0,0,0,.06); }
  .composer textarea { width: 100%; border: 1px solid #e5e7eb; border-radius: 8px;
         padding: 10px; font-size: 14px; resize: vertical; min-height: 64px;
         font-family: inherit; }
  .composer textarea:focus { outline: none; border-color: #3b82f6; }
  .composer .bottom { display: flex; align-items: center; margin-top: 8px; }
  .composer .hint { flex: 1; font-size: 12px; color: #9ca3af; }
  .composer .send { background: #3b82f6; color: #fff;
         border: none; border-radius: 8px; padding: 8px 20px; font-size: 14px; cursor: pointer; }
  .composer .send:hover { background: #2563eb; }
  .chat-box { margin-top: 12px; max-height: 420px; overflow-y: auto; display: flex;
         flex-direction: column; gap: 8px; padding: 4px 0; }
  .msg { max-width: 80%; padding: 8px 14px; border-radius: 12px; position: relative;
         word-break: break-all; white-space: pre-wrap; line-height: 1.5; font-size: 14px; }
  .msg.self { align-self: flex-end; background: #3b82f6; color: #fff; border-bottom-right-radius: 4px; }
  .msg.other { align-self: flex-start; background: #fff; color: #222; border-bottom-left-radius: 4px;
         box-shadow: 0 1px 2px rgba(0,0,0,.06); }
  .msg .nick { font-size: 11px; opacity: .7; margin-bottom: 2px; }
  .msg.self .nick { color: rgba(255,255,255,.8); }
  .msg.other .nick { color: #9ca3af; }
  .msg .meta { font-size: 11px; opacity: .6; margin-top: 3px; display: flex; align-items: center; gap: 6px; }
  .msg .meta button { font-size: 11px; border: none; background: none; cursor: pointer;
         padding: 2px 6px; border-radius: 4px; opacity: .7; }
  .msg.self .meta button { color: #fff; }
  .msg.self .meta button:hover { background: rgba(255,255,255,.2); }
  .msg.other .meta button { color: #6b7280; }
  .msg.other .meta button:hover { background: #f3f4f6; }
  .msg .meta .del-btn { color: inherit; opacity: .5; }
  .msg .meta .del-btn:hover { opacity: 1; }
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

  <h2>💬 聊天室</h2>
  <div class="nick-bar">
    <span>昵称:</span>
    <input type="text" id="nickInput" maxlength="16" spellcheck="false">
  </div>
  <div class="composer">
    <textarea id="msgInput" placeholder="输入消息… Ctrl+Enter 发送"></textarea>
    <div class="bottom">
      <span class="hint">Ctrl+Enter 发送</span>
      <button class="send" id="msgSend">发送</button>
    </div>
  </div>
  <div class="chat-box" id="chatBox"></div>
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

// ---- 聊天室 ----
const msgInput = document.getElementById('msgInput');
const msgSend = document.getElementById('msgSend');
const chatBox = document.getElementById('chatBox');
const nickInput = document.getElementById('nickInput');

// 昵称管理
function getMyNick() {
  let n = localStorage.getItem('lan_chat_nick');
  if (!n) { n = '用户' + Math.random().toString(16).slice(2,5).toUpperCase(); localStorage.setItem('lan_chat_nick', n); }
  return n;
}
nickInput.value = getMyNick();
nickInput.addEventListener('change', () => {
  const v = nickInput.value.trim().slice(0,16) || getMyNick();
  nickInput.value = v;
  localStorage.setItem('lan_chat_nick', v);
});

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
      body: JSON.stringify({ text, nickname: getMyNick() })
    });
    if (res.ok) { msgInput.value = ''; }
    else { const e = await res.json(); alert(e.error || '发送失败'); }
  } finally { msgSend.disabled = false; }
}

function renderMsg(m) {
  const isSelf = m.nickname === getMyNick();
  const cls = isSelf ? 'msg self' : 'msg other';
  return `<div class="${cls}" id="msg-${m.id}">
    <div class="nick">${escapeHtml(m.nickname || m.ip)}</div>
    <span class="msg-text">${escapeHtml(m.text)}</span>
    <div class="meta"><span>${m.time}</span>
      <button onclick="copyMsg(${m.id},this)">复制</button>
      <button class="del-btn" onclick="delMsg(${m.id})">删除</button>
    </div>
  </div>`;
}

async function loadMessages() {
  const res = await fetch('/api/messages');
  const items = await res.json();
  chatBox.innerHTML = items.slice().reverse().map(renderMsg).join('');
  chatBox.scrollTop = chatBox.scrollHeight;
}

function appendMsg(m) {
  chatBox.insertAdjacentHTML('beforeend', renderMsg(m));
  chatBox.scrollTop = chatBox.scrollHeight;
}

function removeMsg(id) {
  const el = document.getElementById('msg-' + id);
  if (el) el.remove();
}

function copyMsg(id, btn) {
  const el = document.querySelector('#msg-' + id + ' .msg-text');
  if (!el) return;
  const text = el.textContent;
  try {
    navigator.clipboard.writeText(text).then(() => {
      const old = btn.textContent; btn.textContent = '已复制';
      setTimeout(() => btn.textContent = old, 1200);
    });
  } catch {
    const r = document.createRange(); r.selectNode(el);
    const sel = getSelection(); sel.removeAllRanges(); sel.addRange(r);
    try { document.execCommand('copy'); } catch {}
    sel.removeAllRanges();
    const old = btn.textContent; btn.textContent = '已复制';
    setTimeout(() => btn.textContent = old, 1200);
  }
}

async function delMsg(id) {
  await fetch('/api/messages/' + id, { method: 'DELETE' });
}

// SSE 实时连接
let msgPollTimer = null;
function startPolling() {
  if (!msgPollTimer) msgPollTimer = setInterval(loadMessages, 4000);
}
function stopPolling() {
  if (msgPollTimer) { clearInterval(msgPollTimer); msgPollTimer = null; }
}

function connectSSE() {
  const es = new EventSource('/api/messages/stream');
  es.addEventListener('message', e => { try { appendMsg(JSON.parse(e.data)); } catch {} });
  es.addEventListener('delete', e => { try { removeMsg(JSON.parse(e.data).id); } catch {} });
  es.onopen = () => stopPolling();
  es.onerror = () => { es.close(); startPolling(); setTimeout(connectSSE, 5000); };
}

loadFiles();
loadMessages();
setInterval(loadFiles, 4000);
connectSSE();
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
    nickname = (data.get("nickname") or "").strip()[:16] or "匿名"
    with _messages_lock:
        _msg_seq += 1
        msg = {
            "id": _msg_seq,
            "text": text,
            "nickname": nickname,
            "ip": request.remote_addr or "?",
            "time": datetime.now().strftime("%H:%M:%S"),
        }
        _messages.insert(0, msg)
        del _messages[MAX_MESSAGES:]
    _broadcast("message", msg)
    return jsonify(msg)


@app.route("/api/messages/<int:msg_id>", methods=["DELETE"])
def delete_message(msg_id):
    with _messages_lock:
        before = len(_messages)
        _messages[:] = [m for m in _messages if m["id"] != msg_id]
        deleted = before != len(_messages)
    if not deleted:
        abort(404)
    _broadcast("delete", {"id": msg_id})
    return jsonify({"deleted": msg_id})


@app.route("/api/messages/stream")
def message_stream():
    q = queue.Queue(maxsize=64)
    with _sse_clients_lock:
        _sse_clients.append(q)

    @stream_with_context
    def generate():
        try:
            while True:
                try:
                    payload = q.get(timeout=25)
                    yield payload
                except queue.Empty:
                    yield ": heartbeat\n\n"
        except GeneratorExit:
            pass
        finally:
            with _sse_clients_lock:
                if q in _sse_clients:
                    _sse_clients.remove(q)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


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
