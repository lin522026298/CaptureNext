# 发布检查与可重复验收

## 范围

本发布只包含审查后的源码快照、合成测试、Windows 便携程序及必要许可。开发仓库历史、真实聊天／附件、账号映射、微信客户端 DLL、keyring、正式状态、私人恢复点和本机验收材料不发布。源码获取与自己的微信数据访问是两件事；没有对应合法 key 不能直接解开任意微信库。

## 可以自己复现的检查

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-build.lock
.\.venv\Scripts\python.exe -m unittest discover -s tests -q
.\.venv\Scripts\python.exe -m unittest discover -s wechat_capture_v2/tests -q
.\.venv\Scripts\python.exe -m unittest discover -s wechat_capture_next/tests -q
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-portable.ps1 -SkipInstall
.\.venv\Scripts\python.exe scripts\smoke-portable.py --app .\app --out .\working\synthetic-release-check
```

所有测试材料是运行时合成的。最后一个命令用打包后的后台完成首次配置、采集、自动联合归并、查看与前后文、旧消息回填、内容修订、停采后追平、深度核验、无变化备份复用、成套恢复及离线查看；不操作桌面、不读真实微信、不取真实 key。`--out` 必须是全新目录，结果保存在其中的 `RESULT.private.json`。测试需完整源码树和测试环境；便携包普通运行不需要 Python。

## 发布安全证据口径

- 静态扫描与人工审查并用：扫描器命中不是自动认定漏洞，扫描零命中也不是绝对安全保证。格式兼容中的 MD5／AES-ECB 不被冒充现代认证设计；档案完整性使用 SHA-256、页认证和恢复回读。
- Git 仅发布新的干净历史，不推送本地研究分支。检查提交对象，不只看 `.gitignore`。`SOURCE-MANIFEST.json` 记录源文件字节数与 SHA-256；克隆时保持原始行尾，避免悄悄改变认证解释绑定。
- 直接及完整锁定 Python 包接受已知漏洞查询。原生 Python 解释器、Windows、WebView2 Runtime、系统多媒体编解码和全部二进制库不是 Python 包扫描的完整覆盖范围，不声称不存在未知漏洞。请保持操作系统与 WebView2 Runtime 安全更新。
- 便携包只允许程序、网页、许可及说明文件；不从工作目录递归打包。扫描程序字符串、嵌入源码和嵌套归档，排查真实配置／密钥／开发用户路径。
- 从 GitHub 无凭据重新获取仓库和发行包，核对哈希，再用重新下载的包执行合成验收；上传成功不是下载可用的证明。
- 发布前再进行隔离上下文独立审查。首次安装不继承作者的档案；新安装的“无外部历史附件来源”回执不等于宣称微信原生所有附件齐全。

## 已知边界

Windows x64 与 Python 3.11 构建环境。独立窗口需要 Microsoft WebView2 Runtime。程序未签名，可能触发未知发布者提醒。不能从客户端未落盘的数据推导手机完整历史；媒体未知关联、缺失和不支持格式必须保持可见。低层旧命令只作维护用途，不是新版成套备份入口。
