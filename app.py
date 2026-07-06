#!/usr/bin/env python3
"""局域网文件传输工具 — 启动后局域网内任意设备用浏览器访问即可上传/下载文件。"""
import io
import json
import os
import re
import sys
import time
import queue
import socket
import platform
import argparse
import threading
import unicodedata
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from flask import (
    Flask,
    Response,
    request,
    jsonify,
    send_from_directory,
    send_file,
    abort,
    render_template_string,
    stream_with_context,
)

__version__ = "1.7.0"

# 配置文件目录(平台相关,不依赖 SHARE_DIR)
if platform.system() == "Windows":
    _CONFIG_DIR = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))) / "lan-drop"
else:
    _CONFIG_DIR = Path.home() / ".config" / "lan-drop"
_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
_CONFIG_FILE = _CONFIG_DIR / "config.json"

# 共享目录 — 在 main() 中根据 config/CLI/环境变量动态设置
SHARE_DIR: Optional[Path] = None

# 共享文本消息(内存存储,服务重启后清空)
MAX_MESSAGES = 200
_messages = []
_messages_lock = threading.Lock()
_msg_seq = 0

# SSE 客户端管理
MAX_SSE_CLIENTS = 50  # 同时在线连接上限,防止恶意/狂刷累积常驻线程
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


def _broadcast_presence():
    """广播当前在线人数(以 SSE 连接数为准)。"""
    with _sse_clients_lock:
        count = len(_sse_clients)
    _broadcast("presence", {"count": count})


# ---- 速率限制 ----
class RateLimiter:
    """简单的滑动窗口速率限制器,按 IP 计数。"""

    def __init__(self, max_req: int, window_sec: float):
        self.max_req = max_req
        self.window = window_sec
        self._store: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def check(self, ip: str) -> bool:
        """返回 True 表示允许,False 表示被限流。"""
        now = time.time()
        with self._lock:
            times = self._store.get(ip, [])
            # 惰性清理过期记录
            cutoff = now - self.window
            while times and times[0] <= cutoff:
                times.pop(0)
            if len(times) >= self.max_req:
                return False
            times.append(now)
            self._store[ip] = times
            # 定期全量清理过期 IP,防止内存膨胀
            if len(self._store) > 500:
                self._store = defaultdict(list, {
                    k: v for k, v in self._store.items()
                    if any(t > cutoff for t in v)
                })
            return True


_msg_limiter = RateLimiter(10, 10)      # 消息: 10 条 / 10 秒
_upload_limiter = RateLimiter(30, 60)   # 上传: 30 次 / 分钟
_delete_limiter = RateLimiter(20, 60)   # 删除: 20 次 / 分钟


# ---- 配置管理 ----
def _load_config() -> dict:
    """加载配置文件,不存在则返回默认值。"""
    default = {
        "autostart": False,
        "share_dir": str(Path("shared").resolve()),
        "port": 9000,
        "host": "0.0.0.0",
    }
    if _CONFIG_FILE.is_file():
        try:
            with open(_CONFIG_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
            if isinstance(saved, dict):
                return {**default, **{k: v for k, v in saved.items() if k in default}}
        except (json.JSONDecodeError, OSError):
            pass
    return dict(default)


def _save_config(cfg: dict):
    """保存配置到文件。"""
    try:
        with open(_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
    except OSError:
        pass


# ---- 开机自启 ----
def _get_startup_dir() -> Optional[Path]:
    """返回操作系统的自启目录路径。"""
    if platform.system() == "Windows":
        p = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        return p if p.parent.parent.parent.exists() else None
    # Linux
    d = Path.home() / ".config" / "autostart"
    return d


def _get_autostart_path() -> Optional[Path]:
    """返回自启入口文件路径(Windows 为 .vbs, Linux 为 .desktop)。"""
    d = _get_startup_dir()
    if d is None:
        return None
    if platform.system() == "Windows":
        return d / "lan-drop.vbs"
    return d / "lan-drop.desktop"


def _check_autostart() -> bool:
    """检查自启文件是否实际存在(可能跟配置不一致)。"""
    p = _get_autostart_path()
    return p.is_file() if p else False


def _apply_autostart(enable: bool):
    """创建或删除开机自启入口。"""
    path = _get_autostart_path()
    if path is None:
        return
    if enable:
        dir_ = path.parent
        dir_.mkdir(parents=True, exist_ok=True)
        if getattr(sys, "frozen", False):
            # PyInstaller 打包的 exe
            vbs = f'CreateObject("Wscript.Shell").Run """{sys.executable}""", 0, False'
        else:
            # Python 脚本 — 用 pythonw.exe 无窗口启动
            pythonw = str(Path(sys.executable).parent / "pythonw.exe")
            script = os.path.abspath(sys.argv[0])
            vbs = f'CreateObject("Wscript.Shell").Run """{pythonw}"" ""{script}""", 0, False'
        with open(path, "w") as f:
            f.write(vbs)
    else:
        if path.exists():
            path.unlink()


# ---- 消息持久化 ----
# CHAT_FILE / LOG_FILE 在 main() 中根据最终 SHARE_DIR 设置
CHAT_FILE: Optional[Path] = None


def _save_messages():
    """将当前消息写入持久化文件。"""
    try:
        with _messages_lock:
            with open(CHAT_FILE, "w", encoding="utf-8") as f:
                json.dump(list(_messages), f, ensure_ascii=False)
    except OSError:
        pass  # 写入失败不阻塞正常流程


def _load_messages():
    """启动时从持久化文件恢复消息。"""
    global _msg_seq
    if not CHAT_FILE.is_file():
        return
    try:
        with open(CHAT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            return
        with _messages_lock:
            _messages[:] = data[-MAX_MESSAGES:]
            if _messages:
                _msg_seq = max(m["id"] for m in _messages)
    except (json.JSONDecodeError, OSError, KeyError):
        pass


# ---- 操作日志 ----
LOG_FILE: Optional[Path] = None  # 在 main() 中设置
_log_lock = threading.Lock()

# 局域网访问地址,在 main() 启动时设置,供 QR 码 API 使用
_lan_url: Optional[str] = None


def _log_operation(action: str, filename: str, ip: str):
    """追加一行操作日志:时间\tIP\t动作\t文件名。"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{timestamp}\t{ip}\t{action}\t{filename}\n"
    try:
        with _log_lock:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line)
    except OSError:
        pass

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


_target_lock = threading.Lock()  # 保护 unique_target 的 check-then-create


def unique_target(filename: str) -> Path:
    """同名文件自动加序号,避免覆盖已有文件(线程安全)。"""
    with _target_lock:
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
  .share-dir { font-size: 11px; color: #9ca3af; margin-bottom: 12px;
               word-break: break-all; background: #fff; display: inline-block;
               padding: 3px 10px; border-radius: 6px; }
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
  .cat-header { display: flex; align-items: center; padding: 9px 16px;
         background: #f9fafb; border-bottom: 1px solid #f0f1f3; cursor: pointer;
         user-select: none; font-size: 13px; font-weight: 500; color: #4b5563; }
  .cat-header:hover { background: #f3f4f6; }
  .cat-chevron { font-size: 10px; margin-right: 6px; width: 14px; text-align: center;
                  transition: transform .15s; display: inline-block; }
  .cat-chevron.open { transform: rotate(90deg); }
  .cat-count { margin-left: auto; font-size: 11px; color: #6b7280;
               background: #e5e7eb; border-radius: 10px; padding: 1px 8px; }
  .cat-body .row { padding-left: 36px; }
  .search-box { display: flex; align-items: center; gap: 8px; margin: 12px 0;
         background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 8px 12px; }
  .search-box:focus-within { border-color: #3b82f6; }
  .search-icon { font-size: 16px; }
  .search-box input { flex: 1; border: none; outline: none; font-size: 14px;
         font-family: inherit; background: transparent; }
  h2 { font-size: 15px; margin: 24px 0 10px; color: #374151; }
  .online { font-size: 12px; font-weight: normal; color: #10b981; margin-left: 6px; }
  .online.off { color: #9ca3af; }
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
  .chat-box { margin-top: 12px; max-height: 420px; overflow-y: auto; padding: 10px; background: #f9fafb; border-radius: 12px; }
  .msg-row { display: flex; gap: 8px; margin-bottom: 6px; align-items: flex-start;
             animation: msgIn .3s ease; }
  .msg-row.self { flex-direction: row-reverse; }
  @keyframes msgIn { from { opacity: 0; transform: translateY(10px); }
                     to { opacity: 1; transform: translateY(0); } }
  .msg-avatar { width: 32px; height: 32px; border-radius: 50%; display: flex;
                align-items: center; justify-content: center; font-size: 13px;
                font-weight: 600; color: #fff; flex-shrink: 0; line-height: 1; }
  .msg-bubble { max-width: 75%; }
  .msg-nick { font-size: 11px; margin-bottom: 2px; padding: 0 6px; color: #6b7280; }
  .msg-row.self .msg-nick { text-align: right; }
  .msg-body { padding: 9px 14px; border-radius: 18px; font-size: 14px;
              line-height: 1.5; word-break: break-all; white-space: pre-wrap; }
  .msg-row.self .msg-body { background: #3b82f6; color: #fff; border-bottom-right-radius: 4px; }
  .msg-row.other .msg-body { background: #fff; color: #222; border-bottom-left-radius: 4px;
                             box-shadow: 0 1px 2px rgba(0,0,0,.06); }
  .msg-actions { display: flex; align-items: center; gap: 4px; margin-top: 2px;
                 padding: 0 6px; opacity: 0; transition: opacity .15s; }
  .msg-bubble:hover .msg-actions { opacity: 1; }
  .msg-row.self .msg-actions { justify-content: flex-end; }
  .msg-time { font-size: 10px; opacity: .6; }
  .msg-row.self .msg-time { color: rgba(255,255,255,.5); }
  .msg-row.other .msg-time { color: #b0b7c3; }
  .msg-actions button { font-size: 10px; border: none; background: none; cursor: pointer;
                        padding: 2px 6px; border-radius: 4px; }
  .msg-row.self .msg-actions button { color: rgba(255,255,255,.6); }
  .msg-row.self .msg-actions button:hover { background: rgba(255,255,255,.15); color: #fff; }
  .msg-row.other .msg-actions button { color: #9ca3af; }
  .msg-row.other .msg-actions button:hover { background: #f3f4f6; color: #6b7280; }
  .settings { background: #fff; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,.06);
              padding: 14px 16px; margin-top: 20px; }
  .settings summary { font-size: 15px; color: #374151; cursor: pointer; user-select: none; }
  .settings summary:focus { outline: none; }
  .settings .body { margin-top: 12px; display: flex; flex-direction: column; gap: 12px; }
  .settings .row { display: flex; align-items: center; gap: 10px; font-size: 13px;
                    color: #6b7280; border-bottom: none; padding: 0; }
  .settings .row label { min-width: 70px; }
  .toggle { position: relative; display: inline-block; width: 40px; height: 22px; }
  .toggle input { opacity: 0; width: 0; height: 0; }
  .toggle .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0;
                    background: #d1d5db; border-radius: 22px; transition: .2s; }
  .toggle .slider::before { content: ""; position: absolute; height: 16px; width: 16px;
                            left: 3px; bottom: 3px; background: #fff; border-radius: 50%;
                            transition: .2s; }
  .toggle input:checked + .slider { background: #3b82f6; }
  .toggle input:checked + .slider::before { transform: translateX(18px); }
  .settings input[type="text"] { flex: 1; border: 1px solid #e5e7eb; border-radius: 6px;
         padding: 5px 8px; font-size: 13px; font-family: inherit; }
  .settings input[type="text"]:focus { outline: none; border-color: #3b82f6; }
  .settings .save-btn { background: #3b82f6; color: #fff; border: none; border-radius: 8px;
         padding: 7px 18px; font-size: 13px; cursor: pointer; align-self: flex-start; }
  .settings .save-btn:hover { background: #2563eb; }
  .settings .hint { font-size: 11px; color: #f59e0b; }
  #notify { position: fixed; bottom: 24px; right: 24px; z-index: 1000; max-width: 320px; }
  .toast { background: #10b981; color: #fff; padding: 12px 16px; border-radius: 8px;
           box-shadow: 0 4px 12px rgba(0,0,0,.15); font-size: 14px; cursor: pointer;
           margin-bottom: 8px; animation: slideIn .3s ease; }
  .toast:hover { background: #059669; }
  @keyframes slideIn { from { transform: translateX(400px); opacity: 0; }
                       to { transform: translateX(0); opacity: 1; } }
  .toast.fade-out { animation: fadeOut .3s ease forwards; }
  @keyframes fadeOut { to { opacity: 0; transform: translateY(10px); } }
  .row.highlight { animation: highlight 1s ease; }
  @keyframes highlight { 0%, 100% { background: transparent; }
                         50% { background: #fef3c7; } }
  .sel-bar { display: flex; align-items: center; gap: 10px; padding: 8px 14px;
             background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 8px;
             margin-bottom: 10px; font-size: 13px; }
  .sel-bar .sel-cb { width: 15px; height: 15px; cursor: pointer; accent-color: #3b82f6;
                     margin: 0 2px; }
  .sel-count { color: #3b82f6; font-weight: 500; margin: 0 6px; }
  .sel-bar button { border: none; background: none; cursor: pointer; font-size: 13px;
                    padding: 5px 12px; border-radius: 6px; }
  .sel-bar .sel-clear { color: #6b7280; margin-left: auto; }
  .sel-bar .sel-clear:hover { background: #e5e7eb; }
  .sel-bar .sel-del { color: #fff; background: #ef4444; }
  .sel-bar .sel-del:hover { background: #dc2626; }
  .row .row-cb { width: 16px; height: 16px; cursor: pointer; accent-color: #3b82f6;
                 flex-shrink: 0; margin-right: 2px; }
  .qr-box { display: flex; align-items: center; gap: 10px; background: #fff;
            border-radius: 10px; padding: 8px 12px; margin-bottom: 12px;
            box-shadow: 0 1px 2px rgba(0,0,0,.04); }
  .qr-img { width: 68px; height: 68px; border-radius: 6px; flex-shrink: 0; }
  .qr-text { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
  .qr-label { font-size: 11px; color: #9ca3af; }
  .qr-addr { font-size: 12px; color: #3b82f6; word-break: break-all; }
  .qr-copy { font-size: 18px; border: none; background: none; cursor: pointer;
             padding: 4px 6px; border-radius: 6px; flex-shrink: 0; line-height: 1; }
  .qr-copy:hover { background: #f3f4f6; }
</style>
</head>
<body>
<div class="wrap">
  <h1>📁 局域网文件传输 <span class="ver">v{{ version }}</span></h1>
  <div class="share-dir">📂 {{ share_dir }}</div>
  <div class="qr-box" id="qrBox">
    <img class="qr-img" src="/api/qrcode" alt="QR" onerror="this.parentElement.style.display='none'">
    <div class="qr-text">
      <span class="qr-label">📱 手机扫码访问</span>
      <span class="qr-addr">{{ lan_url }}</span>
    </div>
    <button class="qr-copy" onclick="copyLanUrl()" title="复制地址">📋</button>
  </div>
  <div class="drop" id="drop">
    <p><strong>点击选择</strong> 或拖拽文件到此处上传</p>
    <p style="margin-top:6px;font-size:12px;">局域网内任意设备均可下载</p>
  </div>
  <input type="file" id="picker" multiple hidden>
  <div id="bars"></div>
  <div class="search-box">
    <span class="search-icon">🔍</span>
    <input type="text" id="searchInput" placeholder="搜索文件..." spellcheck="false">
  </div>
  <div class="sel-bar" id="selBar" style="display:none">
    <input type="checkbox" class="sel-cb" id="selectAllCb" onchange="toggleSelectAll(this)" title="全选/取消全选">
    <span class="sel-count" id="selCount">已选 0 个</span>
    <button class="sel-clear" onclick="clearSelection()">取消选择</button>
    <button class="sel-del" onclick="batchDelete()">批量删除</button>
  </div>
  <div class="list" id="list"><div class="empty">加载中…</div></div>

  <h2>💬 聊天室 <span id="online" class="online">● 在线 1</span></h2>
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

  <details class="settings" id="settingsPanel">
    <summary>⚙️ 设置</summary>
    <div class="body">
      <div class="row">
        <label>开机自启</label>
        <label class="toggle">
          <input type="checkbox" id="autoStartToggle" onchange="saveConfig()">
          <span class="slider"></span>
        </label>
      </div>
      <div class="row">
        <label>保存目录</label>
        <input type="text" id="shareDirInput" spellcheck="false">
      </div>
      <button class="save-btn" onclick="saveConfig()">保存</button>
      <span class="hint" id="restartHint" style="display:none">⚠ 目录/端口/地址修改后需重启生效</span>
    </div>
  </details>
</div>
<script>
const drop = document.getElementById('drop');
const picker = document.getElementById('picker');
const bars = document.getElementById('bars');
const list = document.getElementById('list');
const searchInput = document.getElementById('searchInput');

drop.onclick = () => picker.click();
picker.onchange = () => { uploadFiles(picker.files); picker.value = ''; };
['dragover','dragenter'].forEach(e =>
  drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.add('over'); }));
['dragleave','drop'].forEach(e =>
  drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.remove('over'); }));
drop.addEventListener('drop', ev => uploadFiles(ev.dataTransfer.files));

// 搜索框实时过滤
let searchTimeout;
searchInput.addEventListener('input', () => {
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(() => {
    renderFiles(allFiles, searchInput.value.trim());
  }, 300);
});

	// Ctrl+V 粘贴上传(不在输入框内粘贴时触发)
	document.addEventListener('paste', e => {
	  if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
	  const items = e.clipboardData?.items;
	  if (!items) return;
	  const files = [];
	  for (const item of items) {
	    if (item.kind === 'file') files.push(item.getAsFile());
	  }
	  if (files.length) { e.preventDefault(); uploadFiles(files); }
	});

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
    if (xhr.status === 200) {
      try {
        const r = JSON.parse(xhr.responseText);
        if (r.error) { bar.querySelector('div').textContent = '❌ ' + r.error; return; }
        fill.style.width = '100%';
        setTimeout(() => bar.remove(), 800);
        loadFiles();
        // 显示上传成功通知
        if (r.saved && r.saved.length) {
          showNotify(`✅ ${r.saved.length} 个文件已上传`, r.saved[0].name);
        }
        return;
      } catch {}
    }
    bar.querySelector('div').textContent = '❌ 上传失败 (' + xhr.status + ')';
  };
  xhr.onerror = () => { bar.querySelector('div').textContent = '❌ 上传失败: ' + total; };
  xhr.send(fd);
}

function showNotify(msg, firstFilename) {
  const notify = document.getElementById('notify');
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.textContent = msg;
  toast.onclick = () => {
    // 清空搜索、滚动到文件并高亮
    searchInput.value = '';
    renderFiles(allFiles, '');
    setTimeout(() => {
      const rows = list.querySelectorAll('.row .name');
      for (const row of rows) {
        if (row.textContent === firstFilename) {
          row.closest('.row').scrollIntoView({ behavior: 'smooth', block: 'center' });
          row.closest('.row').classList.add('highlight');
          setTimeout(() => row.closest('.row').classList.remove('highlight'), 1000);
          break;
        }
      }
    }, 100);
    toast.classList.add('fade-out');
    setTimeout(() => toast.remove(), 300);
  };
  notify.innerHTML = ''; // 清除旧通知
  notify.appendChild(toast);
  setTimeout(() => {
    toast.classList.add('fade-out');
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// 文件类型分类
const FILE_CATS = [
  ['🖼️ 图片',   'jpg jpeg png gif bmp svg webp ico heic tiff tif raw'],
  ['📄 文档',   'pdf doc docx xls xlsx ppt pptx txt md csv json xml html rtf odt'],
  ['🎬 视频',   'mp4 avi mkv mov wmv flv webm m4v mpg mpeg 3gp'],
  ['🎵 音频',   'mp3 wav flac aac ogg wma m4a opus'],
  ['📦 压缩包', 'zip rar 7z tar gz bz2 xz iso dmg'],
];

function getCat(filename) {
  const ext = filename.split('.').pop().toLowerCase();
  for (const [cat, exts] of FILE_CATS) {
    if (exts.includes(ext)) return cat;
  }
  return '📁 其他';
}

let allFiles = [];
let selectedFiles = new Set();

async function loadFiles() {
  const res = await fetch('/api/files');
  allFiles = await res.json();
  renderFiles(allFiles);
}

function renderFiles(files, searchQuery = '') {
  // 清理已不在列表中的选中项
  const currentNames = new Set(allFiles.map(f => f.name));
  for (const n of selectedFiles) { if (!currentNames.has(n)) selectedFiles.delete(n); }

  if (!files.length) {
    list.innerHTML = '<div class="empty">暂无文件,上传一个试试</div>';
    updateSelBar();
    return;
  }

  // 搜索过滤
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    files = files.filter(f => f.name.toLowerCase().includes(q));
    if (!files.length) {
      list.innerHTML = '<div class="empty">未找到匹配文件</div>';
      updateSelBar();
      return;
    }
    // 搜索模式：平铺显示，不分组
    list.innerHTML = files.map(f => `
      <div class="row">
        <input type="checkbox" class="row-cb" data-name="${escapeHtml(f.name)}" ${selectedFiles.has(f.name) ? 'checked' : ''} onchange="toggleSelect(this)">
        <span class="name">${escapeHtml(f.name)}</span>
        <span class="meta">${f.size_h} · ${f.mtime}</span>
        <a href="/download/${encodeURIComponent(f.name)}">下载</a>
        <button class="del" onclick="del('${encodeURIComponent(f.name)}')">删除</button>
      </div>`).join('');
    updateSelBar();
    return;
  }

  // 分组模式
  const order = FILE_CATS.map(c => c[0]).concat(['📁 其他']);
  const groups = {};
  for (const f of files) {
    const cat = getCat(f.name);
    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(f);
  }

  let html = '';
  for (const cat of order) {
    const items = groups[cat];
    if (!items || !items.length) continue;
    const collapsed = localStorage.getItem('lan_cat_' + cat) === '1';
    html += `<div class="cat-header" data-cat="${cat}" onclick="toggleCat(this)">
      <span class="cat-chevron${collapsed ? '' : ' open'}">▶</span>
      <span>${cat}</span>
      <span class="cat-count">${items.length}</span>
    </div>`;
    html += `<div class="cat-body" style="${collapsed ? 'display:none' : ''}">`;
    html += items.map(f => `
      <div class="row">
        <input type="checkbox" class="row-cb" data-name="${escapeHtml(f.name)}" ${selectedFiles.has(f.name) ? 'checked' : ''} onchange="toggleSelect(this)">
        <span class="name">${escapeHtml(f.name)}</span>
        <span class="meta">${f.size_h} · ${f.mtime}</span>
        <a href="/download/${encodeURIComponent(f.name)}">下载</a>
        <button class="del" onclick="del('${encodeURIComponent(f.name)}')">删除</button>
      </div>`).join('');
    html += '</div>';
  }
  list.innerHTML = html;
  updateSelBar();
}

function toggleCat(el) {
  const cat = el.dataset.cat;
  const body = el.nextElementSibling;
  const chevron = el.querySelector('.cat-chevron');
  const collapsed = body.style.display === 'none';
  body.style.display = collapsed ? '' : 'none';
  chevron.classList.toggle('open', collapsed);
  localStorage.setItem('lan_cat_' + cat, collapsed ? '0' : '1');
}

// ---- 多选 / 批量删除 ----
function toggleSelect(cb) {
  const name = cb.dataset.name;
  if (cb.checked) selectedFiles.add(name);
  else selectedFiles.delete(name);
  updateSelBar();
}

function toggleSelectAll(masterCb) {
  if (masterCb.checked) {
    allFiles.forEach(f => selectedFiles.add(f.name));
  } else {
    selectedFiles.clear();
  }
  // 同步所有行内复选框
  list.querySelectorAll('.row-cb').forEach(cb => { cb.checked = masterCb.checked; });
  updateSelBar();
}

function clearSelection() {
  selectedFiles.clear();
  list.querySelectorAll('.row-cb').forEach(cb => { cb.checked = false; });
  updateSelBar();
}

async function batchDelete() {
  const count = selectedFiles.size;
  if (!count) return;
  if (!confirm(`确定删除选中的 ${count} 个文件?`)) return;
  const res = await fetch('/api/files/batch-delete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ files: [...selectedFiles] })
  });
  const data = await res.json();
  // 清除已删除文件的选择状态,刷新列表
  if (data.deleted) data.deleted.forEach(n => selectedFiles.delete(n));
  loadFiles();
}

function updateSelBar() {
  const bar = document.getElementById('selBar');
  const count = selectedFiles.size;
  const total = allFiles.length;
  if (count > 0) {
    bar.style.display = 'flex';
    document.getElementById('selCount').textContent = `已选 ${count} 个`;
    const master = document.getElementById('selectAllCb');
    master.checked = (count === total);
    master.indeterminate = (count > 0 && count < total);
  } else {
    bar.style.display = 'none';
  }
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

function copyLanUrl() {
  const el = document.querySelector('.qr-addr');
  if (!el) return;
  const text = el.textContent;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.querySelector('.qr-copy');
    if (btn) { btn.textContent = '✅'; setTimeout(() => btn.textContent = '📋', 1200); }
  }).catch(() => {});
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

const AVATAR_COLORS = ['#ef4444','#f59e0b','#10b981','#3b82f6','#8b5cf6','#ec4899','#06b6d4','#f97316'];
function avatarFor(name) {
  let h = 0;
  for (let i = 0; i < name.length; i++) { h = ((h << 5) - h) + name.charCodeAt(i); h |= 0; }
  return { char: name.charAt(0).toUpperCase(), color: AVATAR_COLORS[Math.abs(h) % AVATAR_COLORS.length] };
}

function renderMsg(m) {
  const isSelf = m.nickname === getMyNick();
  const av = avatarFor(m.nickname || m.ip);
  return `<div class="msg-row ${isSelf ? 'self' : 'other'}" id="msg-${m.id}">
    <div class="msg-avatar" style="background:${av.color}">${av.char}</div>
    <div class="msg-bubble">
      ${isSelf ? '' : `<div class="msg-nick">${escapeHtml(m.nickname || m.ip)}</div>`}
      <div class="msg-body">${escapeHtml(m.text)}</div>
      <div class="msg-actions">
        <span class="msg-time">${m.time}</span>
        <button onclick="copyMsg(${m.id},this)">复制</button>
        <button onclick="delMsg(${m.id})">删除</button>
      </div>
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
  if (document.getElementById('msg-' + m.id)) return;  // 去重:避免极端时序下重复渲染
  chatBox.insertAdjacentHTML('beforeend', renderMsg(m));
  chatBox.scrollTop = chatBox.scrollHeight;
}

function removeMsg(id) {
  const el = document.getElementById('msg-' + id);
  if (el) el.remove();
}

function copyMsg(id, btn) {
  const el = document.querySelector('#msg-' + id + ' .msg-body');
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

const onlineEl = document.getElementById('online');
function setOnline(count, connected) {
  if (connected) {
    onlineEl.textContent = '● 在线 ' + count;
    onlineEl.classList.remove('off');
  } else {
    onlineEl.textContent = '○ 已断开';
    onlineEl.classList.add('off');
  }
}

function connectSSE() {
  const es = new EventSource('/api/messages/stream');
  es.addEventListener('message', e => { try { appendMsg(JSON.parse(e.data)); } catch {} });
  es.addEventListener('delete', e => { try { removeMsg(JSON.parse(e.data).id); } catch {} });
  es.addEventListener('presence', e => { try { setOnline(JSON.parse(e.data).count, true); } catch {} });
  es.onopen = () => stopPolling();
  es.onerror = () => { es.close(); setOnline(0, false); startPolling(); setTimeout(connectSSE, 5000); };
}

loadFiles();
loadMessages();
setInterval(loadFiles, 4000);
connectSSE();

// ---- 设置面板 ----
const autoStartToggle = document.getElementById('autoStartToggle');
const shareDirInput = document.getElementById('shareDirInput');
const restartHint = document.getElementById('restartHint');

async function loadConfig() {
  try {
    const res = await fetch('/api/config');
    const cfg = await res.json();
    autoStartToggle.checked = cfg.autostart_actual;
    shareDirInput.value = cfg.share_dir || '';
  } catch {}
}

async function saveConfig() {
  const body = { autostart: autoStartToggle.checked };
  const dir = shareDirInput.value.trim();
  if (dir) body.share_dir = dir;
  try {
    const res = await fetch('/api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const cfg = await res.json();
    autoStartToggle.checked = cfg.autostart_actual;
    shareDirInput.value = cfg.share_dir || '';
    if (cfg.restart_required) {
      restartHint.style.display = '';
      setTimeout(() => restartHint.style.display = 'none', 6000);
    }
  } catch {}
}

loadConfig();
</script>
<div id="notify"></div>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(PLACEHOLDER_HTML, version=__version__, share_dir=str(SHARE_DIR), lan_url=_lan_url or "")


@app.route("/api/files")
def list_files():
    files = []
    for p in SHARE_DIR.iterdir():
        if p.is_file() and not p.name.startswith("."):
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
    ip = request.remote_addr or "?"
    if not _upload_limiter.check(ip):
        return jsonify({"error": "请求过于频繁,请稍后再试"}), 429
    uploaded = request.files.getlist("files")
    if not uploaded:
        return jsonify({"error": "没有文件"}), 400
    saved = []
    for f in uploaded:
        if not f.filename:
            continue
        target = unique_target(f.filename)
        f.save(target)
        # 写入后立即验证文件确实存在,防御静默写入失败
        if target.is_file():
            saved.append({"name": target.name, "size": target.stat().st_size})
            _log_operation("UPLOAD", target.name, ip)
    if not saved:
        return jsonify({"error": "所有文件保存失败,请检查磁盘空间或权限"}), 500
    return jsonify({"saved": saved, "dir": str(SHARE_DIR)})


@app.route("/download/<path:filename>")
def download(filename):
    target = safe_target(filename)
    if not target.is_file():
        abort(404)
    _log_operation("DOWNLOAD", target.name, request.remote_addr or "?")
    return send_from_directory(SHARE_DIR, target.name, as_attachment=True)


@app.route("/api/delete/<path:filename>", methods=["POST"])
def delete(filename):
    ip = request.remote_addr or "?"
    if not _delete_limiter.check(ip):
        return jsonify({"error": "请求过于频繁,请稍后再试"}), 429
    target = safe_target(filename)
    if not target.is_file():
        abort(404)
    target.unlink()
    _log_operation("DELETE", target.name, ip)
    return jsonify({"deleted": target.name})


@app.route("/api/files/batch-delete", methods=["POST"])
def batch_delete():
    """批量删除文件。一次请求删除多个,速率限制按一次计算。"""
    ip = request.remote_addr or "?"
    if not _delete_limiter.check(ip):
        return jsonify({"error": "请求过于频繁,请稍后再试"}), 429
    data = request.get_json(silent=True) or {}
    names = data.get("files", [])
    if not names or not isinstance(names, list):
        return jsonify({"error": "没有文件"}), 400
    deleted = []
    for name in names:
        try:
            target = safe_target(name)
            if target.is_file():
                target.unlink()
                deleted.append(target.name)
                _log_operation("DELETE", target.name, ip)
        except Exception:
            pass  # 跳过已被他人删除或非法文件名的
    return jsonify({"deleted": deleted})


@app.route("/api/messages")
def list_messages():
    with _messages_lock:
        return jsonify(list(_messages))


@app.route("/api/messages", methods=["POST"])
def post_message():
    global _msg_seq
    ip = request.remote_addr or "?"
    if not _msg_limiter.check(ip):
        return jsonify({"error": "发言过于频繁,请稍后再试"}), 429
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
            "ip": ip,
            "time": datetime.now().strftime("%H:%M:%S"),
        }
        _messages.insert(0, msg)
        del _messages[MAX_MESSAGES:]
    _save_messages()
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
    _save_messages()
    _broadcast("delete", {"id": msg_id})
    return jsonify({"deleted": msg_id})


@app.route("/api/messages/stream")
def message_stream():
    q = queue.Queue(maxsize=64)
    with _sse_clients_lock:
        if len(_sse_clients) >= MAX_SSE_CLIENTS:
            abort(503, "在线连接数已达上限")
        _sse_clients.append(q)
        count = len(_sse_clients)
    # 给本连接立即推一次当前人数,并通知其他人有新成员加入
    q.put_nowait(f"event: presence\ndata: {json.dumps({'count': count})}\n\n")
    _broadcast_presence()

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
            _broadcast_presence()

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---- 配置 API ----
@app.route("/api/config")
def get_config():
    cfg = _load_config()
    return jsonify({
        **cfg,
        "autostart_actual": _check_autostart(),  # 自启文件实际是否存在
        "version": __version__,
        "startup_dir": str(SHARE_DIR) if SHARE_DIR else "",
    })


@app.route("/api/config", methods=["POST"])
def update_config():
    data = request.get_json(silent=True) or {}
    cfg = _load_config()
    changed = False

    if "autostart" in data:
        val = bool(data["autostart"])
        if val != cfg.get("autostart"):
            cfg["autostart"] = val
            _apply_autostart(val)
            changed = True

    if "share_dir" in data and isinstance(data["share_dir"], str):
        path = data["share_dir"].strip()
        if path and path != cfg.get("share_dir"):
            cfg["share_dir"] = path
            changed = True

    if "port" in data and isinstance(data["port"], int):
        cfg["port"] = data["port"]
        changed = True

    if "host" in data and isinstance(data["host"], str):
        cfg["host"] = data["host"].strip() or "0.0.0.0"
        changed = True

    if changed:
        _save_config(cfg)

    return jsonify({
        **cfg,
        "autostart_actual": _check_autostart(),
        "restart_required": any(k in data for k in ("share_dir", "port", "host")),
    })


@app.route("/api/qrcode")
def qrcode_image():
    """生成局域网访问地址的二维码图片(PNG)。需要安装 qrcode[pil]。"""
    url = _lan_url or ""
    if not url:
        abort(404)
    try:
        import qrcode
    except ImportError:
        abort(404, "qrcode not installed")
    try:
        img = qrcode.make(url, border=2)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        return send_file(buf, mimetype="image/png")
    except Exception:
        abort(404)


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
    global SHARE_DIR, CHAT_FILE, LOG_FILE, _lan_url

    # 1. 加载配置文件
    cfg = _load_config()

    # 2. 解析 CLI 参数(默认 None, 由后续优先级链填充)
    parser = argparse.ArgumentParser(description="局域网文件传输工具")
    parser.add_argument("--port", type=int, default=None, help="监听端口")
    parser.add_argument("--host", default=None, help="监听地址")
    parser.add_argument("--dir", default=None, help="共享目录")
    args = parser.parse_args()

    # 3. 优先级: CLI > 环境变量 > 配置文件 > 默认值
    port = args.port or cfg.get("port", 9000)
    host = args.host or cfg.get("host", "0.0.0.0")
    share_dir = args.dir or os.environ.get("LAN_SHARE_DIR") or cfg.get("share_dir", "shared")

    # 4. 设置全局 SHARE_DIR / CHAT_FILE / LOG_FILE
    SHARE_DIR = Path(share_dir).resolve()
    SHARE_DIR.mkdir(parents=True, exist_ok=True)
    CHAT_FILE = SHARE_DIR / ".chat.json"
    LOG_FILE = SHARE_DIR / ".lan-drop.log"

    # 5. 回写最终值到配置(下次启动时可用)
    cfg["port"] = port
    cfg["host"] = host
    cfg["share_dir"] = str(SHARE_DIR)
    _save_config(cfg)

    # 6. 应用开机自启设置
    _apply_autostart(cfg.get("autostart", False))

    # 7. 恢复聊天消息
    _load_messages()

    # 8. 启动
    ip = get_lan_ip()
    _lan_url = f"http://{ip}:{port}"
    print_banner(ip, port)
    app.run(host=host, port=port, threaded=True)


if __name__ == "__main__":
    main()
