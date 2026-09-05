# MiniSyncDAV 0.1.0

一个专门面向内网多人 SyncClipboard 的轻量 WebDAV 服务。

## 特点

- **纯 Python 标准库**
- **不需要 pip install**
- **不使用数据库**
- 配置：`config.json`
- 用户：`users.json`
- 每个用户一个独立目录
- 注册页面
- 管理页面
- Windows / Linux
- 目标兼容 Python 3.6+

实现的 WebDAV 方法：

`OPTIONS / GET / HEAD / PUT / DELETE / MKCOL / PROPFIND`

这已经覆盖 SyncClipboard WebDAV 后端的主要使用方式。

## 启动

Windows：

```bat
python server.py --root D:\MiniSyncDAV
```

Ubuntu/Linux：

```bash
python3 server.py --root /opt/minisyncdav
```

默认监听：

```text
0.0.0.0:8080
```

启动时会自动显示本机局域网地址。

## 页面

```text
管理：
http://服务器IP:8080/_admin

注册：
http://服务器IP:8080/_register
```

默认管理员：

```text
admin
admin123
```

登录管理后台后可以直接修改管理员密码。

## 用户数据

首次启动后：

```text
MiniSyncDAV_Data/
├─ config.json
├─ users.json
└─ data/
   ├─ user01/
   │  └─ file/
   └─ user02/
      └─ file/
```

用户密码与管理员密码都保存为 PBKDF2-SHA256 哈希，不保存明文。

## SyncClipboard 配置示例

假设服务器：

```text
192.168.15.100
```

端口：

```text
8080
```

那么用户填写：

```text
Server URL:
http://192.168.15.100:8080

User:
user01

Password:
该用户设置的密码
```

URL 建议不要以 `/` 结尾。

用户登录后看到的 WebDAV 根目录实际上就是：

```text
data/user01/
```

其他用户目录完全不会映射给他。

## 当前定位

0.1.0 是专门面向可信内网和 SyncClipboard 的轻量版本。

没有实现：
- HTTPS
- LOCK/UNLOCK
- COPY/MOVE
- 配额
- 完整 RFC WebDAV 全部扩展

如果后续确认 SyncClipboard 实测正常，再按实际需要增加。
