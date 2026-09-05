#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MiniSyncDAV 0.1.0
纯 Python 标准库、内网多用户 WebDAV，主要面向 SyncClipboard。

支持:
- Basic Auth
- 每个账户独立目录
- GET / HEAD / PUT / DELETE / MKCOL / PROPFIND / OPTIONS
- 注册网页
- 管理网页
- JSON 配置，无数据库
- Python 3.6+
"""

from __future__ import print_function

import argparse
import base64
import hashlib
import hmac
import html
import json
import mimetypes
import os
import re
import secrets
import shutil
import socket
import socketserver
import sys
import threading
import time
from datetime import datetime
from email.utils import formatdate
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit
import xml.etree.ElementTree as ET


APP_NAME = "MiniSyncDAV"
VERSION = "0.1.0"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{3,32}$")
FILE_CHUNK = 1024 * 1024
STORE_LOCK = threading.RLock()


def now_http():
    return formatdate(timeval=None, localtime=False, usegmt=True)


def xml_http_date(ts):
    return formatdate(timeval=ts, localtime=False, usegmt=True)


def password_hash(password, iterations=120000):
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return {
        "algo": "pbkdf2_sha256",
        "iterations": iterations,
        "salt": base64.b64encode(salt).decode("ascii"),
        "hash": base64.b64encode(digest).decode("ascii"),
    }


def password_verify(password, record):
    try:
        if record.get("algo") != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(record["salt"])
        expected = base64.b64decode(record["hash"])
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            int(record["iterations"]),
        )
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def atomic_json(path, obj):
    tmp = Path(str(path) + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(str(tmp), str(path))


def load_json(path, default):
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


class Store(object):
    def __init__(self, root):
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.data_dir = self.root / "data"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.config_path = self.root / "config.json"
        self.users_path = self.root / "users.json"

        self.config = load_json(self.config_path, None)
        if self.config is None:
            self.config = {
                "host": "0.0.0.0",
                "port": 8080,
                "registration_enabled": True,
                "admin_user": "admin",
                "admin_password": password_hash("admin123"),
                "session_secret": base64.b64encode(os.urandom(32)).decode("ascii"),
            }
            atomic_json(self.config_path, self.config)

        self.users = load_json(self.users_path, None)
        if self.users is None:
            self.users = {}
            atomic_json(self.users_path, self.users)

    def save_config(self):
        with STORE_LOCK:
            atomic_json(self.config_path, self.config)

    def save_users(self):
        with STORE_LOCK:
            atomic_json(self.users_path, self.users)

    def valid_username(self, username):
        return bool(USERNAME_RE.fullmatch(username or ""))

    def user_root(self, username):
        if not self.valid_username(username):
            raise ValueError("非法用户名")
        p = (self.data_dir / username).resolve()
        if p.parent != self.data_dir.resolve():
            raise ValueError("非法目录")
        return p

    def add_user(self, username, password):
        username = (username or "").strip()
        if not self.valid_username(username):
            raise ValueError("用户名只能包含字母、数字、下划线、连字符，长度 3-32")
        if len(password or "") < 4:
            raise ValueError("密码至少 4 位")
        with STORE_LOCK:
            if username in self.users:
                raise ValueError("用户名已存在")
            root = self.user_root(username)
            root.mkdir(parents=True, exist_ok=True)
            # SyncClipboard 会自己创建 file；提前创建也不影响使用。
            (root / "file").mkdir(parents=True, exist_ok=True)
            self.users[username] = {
                "enabled": True,
                "password": password_hash(password),
                "created_at": int(time.time()),
            }
            self.save_users()

    def authenticate(self, username, password):
        rec = self.users.get(username)
        if not rec or not rec.get("enabled", True):
            return False
        return password_verify(password, rec.get("password", {}))

    def set_enabled(self, username, enabled):
        with STORE_LOCK:
            if username not in self.users:
                raise ValueError("用户不存在")
            self.users[username]["enabled"] = bool(enabled)
            self.save_users()

    def reset_password(self, username, password):
        if len(password or "") < 4:
            raise ValueError("密码至少 4 位")
        with STORE_LOCK:
            if username not in self.users:
                raise ValueError("用户不存在")
            self.users[username]["password"] = password_hash(password)
            self.save_users()

    def delete_user(self, username, delete_data=False):
        with STORE_LOCK:
            if username in self.users:
                del self.users[username]
                self.save_users()
        if delete_data:
            p = self.user_root(username)
            if p.exists():
                shutil.rmtree(str(p))

    def safe_path(self, username, web_path):
        base = self.user_root(username).resolve()
        rel = unquote(web_path.split("?", 1)[0]).replace("\\", "/").lstrip("/")
        parts = []
        for part in rel.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                raise ValueError("非法路径")
            parts.append(part)
        p = base.joinpath(*parts).resolve()
        try:
            p.relative_to(base)
        except ValueError:
            raise ValueError("非法路径")
        return p


class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class MiniDavHandler(BaseHTTPRequestHandler):
    server_version = APP_NAME + "/" + VERSION

    def log_message(self, fmt, *args):
        sys.stdout.write("%s - [%s] %s\n" % (
            self.client_address[0],
            self.log_date_time_string(),
            fmt % args
        ))

    @property
    def store(self):
        return self.server.store

    def send_bytes(self, status, data=b"", content_type="text/plain; charset=utf-8", extra=None):
        self.send_response(status)
        self.send_header("Date", now_http())
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if extra:
            for k, v in extra:
                self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD" and data:
            self.wfile.write(data)

    def send_html(self, status, title, body):
        page = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} - MiniSyncDAV</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;background:#f4f6f8;color:#222;margin:0}}
.wrap{{max-width:900px;margin:30px auto;padding:0 15px}}
.card{{background:#fff;padding:22px;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);margin-bottom:18px}}
input,button{{font:inherit;padding:9px 11px;border:1px solid #ccd1d7;border-radius:7px}}
button{{cursor:pointer}} .primary{{background:#1976d2;color:white;border:0}}
.danger{{background:#c62828;color:white;border:0}}
.warn{{background:#ef6c00;color:white;border:0}}
.row{{display:flex;gap:9px;align-items:center;flex-wrap:wrap}}
table{{width:100%;border-collapse:collapse}} th,td{{padding:10px;border-bottom:1px solid #eee;text-align:left}}
code{{background:#f1f3f5;padding:2px 5px;border-radius:4px}} a{{color:#1976d2;text-decoration:none}}
.msg{{background:#fff3cd;padding:10px;border-radius:7px;margin-bottom:12px}}
.small{{font-size:13px;color:#666}}
</style></head><body><div class="wrap">{body}</div></body></html>""".format(
            title=html.escape(title), body=body
        )
        self.send_bytes(status, page.encode("utf-8"), "text/html; charset=utf-8")

    def read_form(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace")
        parsed = parse_qs(raw, keep_blank_values=True)
        return {k: v[-1] if v else "" for k, v in parsed.items()}

    # ---------- simple admin session ----------
    def make_admin_cookie(self):
        secret = base64.b64decode(self.store.config["session_secret"])
        payload = str(int(time.time()) + 12 * 3600)
        sig = hmac.new(secret, payload.encode("ascii"), hashlib.sha256).hexdigest()
        return payload + "." + sig

    def admin_ok(self):
        cookies = self.headers.get("Cookie", "")
        token = None
        for item in cookies.split(";"):
            item = item.strip()
            if item.startswith("minisyncdav_admin="):
                token = item.split("=", 1)[1]
                break
        if not token or "." not in token:
            return False
        exp, sig = token.split(".", 1)
        try:
            if int(exp) < int(time.time()):
                return False
        except Exception:
            return False
        secret = base64.b64decode(self.store.config["session_secret"])
        expected = hmac.new(secret, exp.encode("ascii"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig)

    def redirect(self, path, cookie=None):
        self.send_response(303)
        self.send_header("Location", path)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ---------- Basic Auth ----------
    def dav_auth(self):
        value = self.headers.get("Authorization", "")
        if not value.startswith("Basic "):
            self.require_auth()
            return None
        try:
            decoded = base64.b64decode(value[6:].strip()).decode("utf-8")
            username, password = decoded.split(":", 1)
        except Exception:
            self.require_auth()
            return None
        if not self.store.authenticate(username, password):
            self.require_auth()
            return None
        return username

    def require_auth(self):
        body = b"Authentication required"
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="MiniSyncDAV"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    # ---------- web UI ----------
    def web_route(self):
        path = urlsplit(self.path).path
        return path.startswith("/_admin") or path.startswith("/_register") or path == "/_"

    def do_web_get(self):
        path = urlsplit(self.path).path
        if path == "/_":
            self.send_html(200, APP_NAME, """
<div class="card">
<h1>MiniSyncDAV</h1>
<p>内网多用户 WebDAV 服务。</p>
<p><a href="/_register">注册账户</a> · <a href="/_admin">管理后台</a></p>
</div>""")
            return

        if path == "/_register":
            if not self.store.config.get("registration_enabled", True):
                self.send_html(200, "注册关闭", '<div class="card"><h2>注册已关闭</h2></div>')
                return
            self.send_html(200, "注册", """
<div class="card"><h2>创建 WebDAV 账户</h2>
<form method="post" action="/_register">
<p><input name="username" placeholder="用户名" required></p>
<p><input type="password" name="password" placeholder="密码" required></p>
<p><input type="password" name="password2" placeholder="确认密码" required></p>
<button class="primary">注册</button>
</form><p class="small">用户名：3-32 位字母、数字、_、-</p></div>""")
            return

        if path == "/_admin/login":
            self.send_html(200, "管理员登录", """
<div class="card"><h2>管理员登录</h2>
<form method="post" action="/_admin/login">
<p><input name="username" placeholder="管理员用户名" required></p>
<p><input type="password" name="password" placeholder="管理员密码" required></p>
<button class="primary">登录</button>
</form></div>""")
            return

        if path == "/_admin":
            if not self.admin_ok():
                self.redirect("/_admin/login")
                return
            rows = []
            for name in sorted(self.store.users):
                rec = self.store.users[name]
                state = "启用" if rec.get("enabled", True) else "禁用"
                toggle_text = "禁用" if rec.get("enabled", True) else "启用"
                rows.append("""
<tr><td>{n}</td><td>{state}</td><td>
<form style="display:inline" method="post" action="/_admin/toggle">
<input type="hidden" name="username" value="{n}"><button>{toggle}</button></form>
<form style="display:inline" method="post" action="/_admin/password">
<input type="hidden" name="username" value="{n}">
<input type="password" name="password" placeholder="新密码" required><button class="warn">改密码</button></form>
<form style="display:inline" method="post" action="/_admin/delete" onsubmit="return confirm('确定删除账户？')">
<input type="hidden" name="username" value="{n}">
<label><input type="checkbox" name="delete_data" value="1">删数据</label>
<button class="danger">删除</button></form>
</td></tr>""".format(n=html.escape(name), state=state, toggle=toggle_text))
            table = "\n".join(rows) if rows else "<tr><td colspan='3'>暂无账户</td></tr>"
            reg = "开放" if self.store.config.get("registration_enabled", True) else "关闭"
            body = """
<div class="card"><div class="row"><h1 style="margin-right:auto">MiniSyncDAV 管理</h1>
<a href="/_admin/logout">退出</a></div>
<p>数据目录：<code>{data}</code></p>
<p>WebDAV 地址：<code>http://服务器IP:{port}</code></p>
<p>注册：<b>{reg}</b></p>
<form method="post" action="/_admin/register-toggle"><button>切换注册状态</button></form>
</div>

<div class="card"><h2>创建账户</h2>
<form class="row" method="post" action="/_admin/add">
<input name="username" placeholder="用户名" required>
<input type="password" name="password" placeholder="密码" required>
<button class="primary">创建</button></form></div>

<div class="card"><h2>修改管理员密码</h2>
<form class="row" method="post" action="/_admin/admin-password">
<input type="password" name="password" placeholder="新管理员密码" required>
<button class="warn">修改</button></form></div>

<div class="card"><h2>账户列表</h2>
<table><tr><th>用户名</th><th>状态</th><th>操作</th></tr>{table}</table></div>
""".format(
                data=html.escape(str(self.store.data_dir)),
                port=int(self.store.config["port"]),
                reg=reg,
                table=table,
            )
            self.send_html(200, "管理后台", body)
            return

        if path == "/_admin/logout":
            self.redirect("/_admin/login", "minisyncdav_admin=; Path=/; Max-Age=0; HttpOnly")
            return

        self.send_html(404, "404", "<div class='card'><h2>页面不存在</h2></div>")

    def do_web_post(self):
        path = urlsplit(self.path).path
        form = self.read_form()

        if path == "/_register":
            if not self.store.config.get("registration_enabled", True):
                self.send_html(403, "注册关闭", "<div class='card'>注册已关闭</div>")
                return
            try:
                if form.get("password") != form.get("password2"):
                    raise ValueError("两次密码不一致")
                self.store.add_user(form.get("username", ""), form.get("password", ""))
                self.send_html(200, "注册成功", """
<div class="card"><h2>注册成功</h2>
<p>用户名：<code>{u}</code></p>
<p>WebDAV 地址：<code>http://服务器IP:{port}</code></p>
<p>SyncClipboard 中 URL 不要以 / 结尾。</p>
</div>""".format(
                    u=html.escape(form.get("username", "")),
                    port=int(self.store.config["port"]),
                ))
            except Exception as e:
                self.send_html(400, "注册失败", "<div class='card'><h2>注册失败</h2><p>{}</p><p><a href='/_register'>返回</a></p></div>".format(html.escape(str(e))))
            return

        if path == "/_admin/login":
            u = form.get("username", "")
            p = form.get("password", "")
            ok = (
                u == self.store.config.get("admin_user", "admin")
                and password_verify(p, self.store.config.get("admin_password", {}))
            )
            if ok:
                self.redirect("/_admin", "minisyncdav_admin=%s; Path=/; HttpOnly; SameSite=Lax" % self.make_admin_cookie())
            else:
                self.send_html(401, "登录失败", "<div class='card'><h2>用户名或密码错误</h2><a href='/_admin/login'>返回</a></div>")
            return

        if not self.admin_ok():
            self.redirect("/_admin/login")
            return

        try:
            if path == "/_admin/add":
                self.store.add_user(form.get("username", ""), form.get("password", ""))
            elif path == "/_admin/toggle":
                u = form.get("username", "")
                rec = self.store.users.get(u)
                if not rec:
                    raise ValueError("用户不存在")
                self.store.set_enabled(u, not rec.get("enabled", True))
            elif path == "/_admin/password":
                self.store.reset_password(form.get("username", ""), form.get("password", ""))
            elif path == "/_admin/delete":
                self.store.delete_user(form.get("username", ""), form.get("delete_data") == "1")
            elif path == "/_admin/register-toggle":
                self.store.config["registration_enabled"] = not self.store.config.get("registration_enabled", True)
                self.store.save_config()
            elif path == "/_admin/admin-password":
                p = form.get("password", "")
                if len(p) < 4:
                    raise ValueError("管理员密码至少 4 位")
                self.store.config["admin_password"] = password_hash(p)
                self.store.save_config()
            else:
                raise ValueError("未知操作")
            self.redirect("/_admin")
        except Exception as e:
            self.send_html(400, "操作失败", "<div class='card'><h2>操作失败</h2><p>{}</p><a href='/_admin'>返回</a></div>".format(html.escape(str(e))))

    # ---------- DAV ----------
    def dav_path(self, username):
        return self.store.safe_path(username, urlsplit(self.path).path)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("DAV", "1")
        self.send_header("Allow", "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, PROPFIND")
        self.send_header("MS-Author-Via", "DAV")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        if self.web_route():
            self.do_web_get()
            return
        self.do_GET()

    def do_GET(self):
        if self.web_route():
            self.do_web_get()
            return
        username = self.dav_auth()
        if not username:
            return
        try:
            p = self.dav_path(username)
        except ValueError:
            self.send_error(403)
            return
        if not p.exists():
            self.send_error(404)
            return
        if p.is_dir():
            # 普通浏览器访问目录时给一个简单提示；WebDAV 客户端用 PROPFIND。
            self.send_html(200, "WebDAV", "<div class='card'><h2>WebDAV 目录</h2><p>请使用 WebDAV 客户端访问。</p></div>")
            return
        try:
            st = p.stat()
            ctype = mimetypes.guess_type(str(p))[0] or "application/octet-stream"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(st.st_size))
            self.send_header("Last-Modified", xml_http_date(st.st_mtime))
            self.end_headers()
            if self.command != "HEAD":
                with p.open("rb") as f:
                    while True:
                        chunk = f.read(FILE_CHUNK)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
        except OSError:
            self.send_error(500)

    def do_PUT(self):
        username = self.dav_auth()
        if not username:
            return
        try:
            p = self.dav_path(username)
            if p == self.store.user_root(username):
                self.send_error(405)
                return
            existed = p.exists()
            p.parent.mkdir(parents=True, exist_ok=True)
            length = int(self.headers.get("Content-Length", "0") or 0)
            remaining = length
            tmp = Path(str(p) + ".uploading")
            with tmp.open("wb") as f:
                while remaining > 0:
                    chunk = self.rfile.read(min(FILE_CHUNK, remaining))
                    if not chunk:
                        break
                    f.write(chunk)
                    remaining -= len(chunk)
            if remaining != 0:
                try:
                    tmp.unlink()
                except Exception:
                    pass
                self.send_error(400, "Incomplete request body")
                return
            os.replace(str(tmp), str(p))
            self.send_response(204 if existed else 201)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except Exception as e:
            self.send_error(500, str(e))

    def do_MKCOL(self):
        username = self.dav_auth()
        if not username:
            return
        try:
            p = self.dav_path(username)
            if p.exists():
                self.send_error(405)
                return
            p.mkdir(parents=True, exist_ok=False)
            self.send_response(201)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except Exception:
            self.send_error(409)

    def do_DELETE(self):
        username = self.dav_auth()
        if not username:
            return
        try:
            p = self.dav_path(username)
            if p == self.store.user_root(username):
                self.send_error(403)
                return
            if not p.exists():
                self.send_error(404)
                return
            if p.is_dir():
                shutil.rmtree(str(p))
            else:
                p.unlink()
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except Exception as e:
            self.send_error(500, str(e))

    def prop_response(self, username, p, href):
        st = p.stat()
        is_dir = p.is_dir()
        display = p.name if p != self.store.user_root(username) else "/"
        size = 0 if is_dir else st.st_size
        lm = xml_http_date(st.st_mtime)
        resource_type = "<D:collection/>" if is_dir else ""
        ctype = "" if is_dir else (mimetypes.guess_type(str(p))[0] or "application/octet-stream")
        if is_dir and not href.endswith("/"):
            href += "/"
        return """<D:response>
<D:href>{href}</D:href>
<D:propstat><D:prop>
<D:displayname>{display}</D:displayname>
<D:getcontentlength>{size}</D:getcontentlength>
<D:getlastmodified>{lm}</D:getlastmodified>
<D:resourcetype>{rtype}</D:resourcetype>
<D:getcontenttype>{ctype}</D:getcontenttype>
</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>
</D:response>""".format(
            href=html.escape(href, quote=True),
            display=html.escape(display),
            size=size,
            lm=lm,
            rtype=resource_type,
            ctype=html.escape(ctype),
        )

    def do_PROPFIND(self):
        username = self.dav_auth()
        if not username:
            return
        try:
            p = self.dav_path(username)
        except ValueError:
            self.send_error(403)
            return
        if not p.exists():
            self.send_error(404)
            return

        depth = self.headers.get("Depth", "1")
        req_path = urlsplit(self.path).path
        if not req_path.startswith("/"):
            req_path = "/" + req_path

        items = [(p, req_path)]
        if depth != "0" and p.is_dir():
            try:
                for child in sorted(p.iterdir(), key=lambda x: x.name.lower()):
                    base = req_path.rstrip("/") + "/"
                    href = base + quote(child.name)
                    if child.is_dir():
                        href += "/"
                    items.append((child, href))
            except OSError:
                pass

        parts = ['<?xml version="1.0" encoding="utf-8"?>',
                 '<D:multistatus xmlns:D="DAV:">']
        for item, href in items:
            parts.append(self.prop_response(username, item, href))
        parts.append("</D:multistatus>")
        data = "".join(parts).encode("utf-8")

        self.send_response(207)
        self.send_header("Content-Type", "application/xml; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.web_route():
            self.do_web_post()
        else:
            self.send_error(405)


def get_lan_ips():
    out = []
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127.") and ip not in out:
                out.append(ip)
    except Exception:
        pass
    return out


def main():
    ap = argparse.ArgumentParser(description="MiniSyncDAV - 内网多用户 WebDAV")
    ap.add_argument("--root", default="./MiniSyncDAV_Data", help="配置和用户数据所在目录")
    ap.add_argument("--host", default=None, help="监听地址，默认读取 config.json")
    ap.add_argument("--port", type=int, default=None, help="监听端口，默认读取 config.json")
    args = ap.parse_args()

    store = Store(args.root)
    host = args.host if args.host is not None else store.config.get("host", "0.0.0.0")
    port = args.port if args.port is not None else int(store.config.get("port", 8080))

    server = ThreadingHTTPServer((host, port), MiniDavHandler)
    server.store = store

    print("=" * 64)
    print("%s %s" % (APP_NAME, VERSION))
    print("Python:", sys.version.split()[0])
    print("数据目录:", store.root)
    print("监听: %s:%s" % (host, port))
    ips = get_lan_ips()
    if ips:
        print("WebDAV:", "  ".join("http://%s:%s" % (ip, port) for ip in ips))
        print("注册页:", "  ".join("http://%s:%s/_register" % (ip, port) for ip in ips))
        print("管理页:", "  ".join("http://%s:%s/_admin" % (ip, port) for ip in ips))
    else:
        print("管理页: http://127.0.0.1:%s/_admin" % port)
    print("默认管理员: admin / admin123")
    print("首次登录后请在管理页面修改管理员密码。")
    print("=" * 64)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n正在退出...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
