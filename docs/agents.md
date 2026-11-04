# 让 Agent 无界面使用 CaptureNext

CaptureNext 的档案能力不依赖鼠标点击。具备本机进程、文件及 loopback HTTP 访问权限的 Agent，可以将用户的自然语言要求转换成产品后台调用，操作与查看器相同的核心功能，而不打开前台 GUI 或浏览器、不接管键鼠。

这里的“支持 Agent”是可编程后台能力，不是工具内置大模型、自然语言解析器、MCP 服务或任意聊天网站的一键连接功能。普通聊天窗口如果没有本机工具权限，不能直接访问你的档案。“无界面”也不等于没有权限要求、没有资源消耗或无需任何人工确认。

## 用户可以怎样交代任务

- “只检查采集、联合归并、附件和最近备份状态，先不要改变任何设置。”
- “查找这个会话上个月的某个关键词，给我前后文及对应来源。”
- “导出这条消息已确认关联的原附件；未知候选不要当作已匹配。”
- “现在做一次成套备份并恢复到新目录，验证后不要接管正式状态。”

Agent 应先区分只读查询与会改变状态的操作。恢复接管、删除、启用含密钥备份、取钥或登录等，必须有相应明确授权；不因一句“帮我查看”顺带执行维护或改设置。

## 功能与后台入口

正常模式下，读取走 `GET`，写操作统一提交到 `POST /api/jobs`。所有动作仍经过既有参数检查、单写者锁和同一任务队列，没有“Agent 绕过校验”通道。

| 任务 | 读取接口或任务 action | 重要边界 |
| --- | --- | --- |
| 状态、最近任务与分项进度 | `/api/product`、`/api/jobs`、`/api/status` | 分别检查采集、归并、附件、备份、核验；排队成功不等于完成 |
| 采集、暂停及补采 | `start_watch`、`stop_watch`、`capture` | 自动归并、去重和索引衔接；只补本机实际落盘内容 |
| 会话、检索、上下文与修订来源 | `/api/conversations`、`/api/union-messages`、`/api/message-context`、`/api/message-detail` | 翻页遍历，不将单页上限当作完整历史；候选不等于确认重复 |
| 附件、图片、语音、视频与文件 | `/api/assets`、`/api/image-candidates`、`/api/attachment-candidates`；`index_media`、`prepare_media`、`prepare_image`、`prepare_attachment`、`verify_attachment`、`export_attachment`、`export_raw_asset`、`load_image_keys` | 使用已有证据及内容库；缺失、未知关联、不支持解码仍分别报告 |
| 来源导入、归并、独立比对与导出 | `import_source`、`sync_union`、`compare`、`export_union` | 来源只读；稳定来源别名；输出必须是允许目录中的全新名称 |
| 成套备份及空间治理 | `/api/union-backups`；`backup_pair`、`snapshot_pin`、`backup_cleanup` | 优先产品成套备份，不以底层单状态备份代替；失败不能淘汰可用恢复点 |
| 完整核验及恢复使用 | `deep_verify`、`restore_pair`、`open_restored`、`close_restored`；恢复模式的 `promote_restore` | 离线阅读与恢复接管是两件事；新目标、材料验证与显式确认不可省略 |
| 计划、设置及 WebUI 开关 | `settings`、`webui` | 设置需提交完整已知字段；开机启动注册及托盘通知由桌面壳实际实施 |

接口及参数以对应版本的 `wechat_capture_next/product.py`、`product_host.py`、`console.py` 和 `recovery_core.py` 为准。恢复模式刻意不提供正常采集动作；离线消息／附件查询须指定 `view=restored`。Agent 能调用已有功能，不意味着可以解码工具不支持的格式或找回未同步的数据。

## 复用唯一后台，不另启写者

若桌面或托盘已在运行，应复用其后台会话；不要再执行 CLI `capture`、`watch`、`union`、`backup`，也不要用第二个后台接管同一正式状态。Agent 需要获授权的本地会话地址及 token；当前没有通用的“自动附加到任意托盘实例”连接器，不要把已在运行误认为可以直接启动第二份。

没有现存写者时，Agent 的本地宿主可直接托管便携包内的 `app/backend-dist/CaptureNextCore/CaptureNextCore.exe --root`，或源码环境中的 `python -m wechat_capture_next.product_host --root`。`--root` 后传安装根目录的本地绝对路径，并将该目录作为工作目录。Windows 下使用重定向管道及 `CREATE_NO_WINDOW`，无需启动 `CaptureNext.exe`、WebView2 或浏览器。首次配置可用同一可执行文件的 `--configure` 非交互参数，见 [配置指南](configuration.md)。

宿主应做到：

1. 先确认没有同状态写者，再创建子进程，重定向 stdin、stdout 和 stderr；不要把握手输出保存到公开日志。
2. 从首行 JSON 取得本次随机 `url`、`token` 和 `mode`，只在本地内存中保存；确认是预期正常／恢复模式，不能把因启动失败进入恢复模式当作采集成功。
3. 只连接本机 loopback，绕过系统 HTTP 代理；API 请求带 `X-Capture-Token`，写请求另带与实际服务地址相同的 `Origin` 和 `Content-Type: application/json`。不对公网开放或转发端口。
4. 保持 stdin 管道打开、持续排空 stderr；异步任务按 ID 查询直到终态，检查错误与分项结果。HTTP 503 可能是维护暂时暂停读取，不要据此另启采集器。
5. 结束自己托管的会话时，在 stdin 写入 `quit` 加换行，并等待安全退出。关闭管道也会触发收尾，因此一次短命令结束后不会凭空留下可靠常驻服务；长期运行需要仍在的宿主或桌面托盘管理。不要强杀进程。

产品后台会遵循已有 `auto_capture` 设置，缺省为开启。为了做“仅查看”任务，不应新启动正式产品后台或改动采集设置；使用现存只读接口，或者显式启动已验证恢复副本的 `--offline` 模式。

以下 Python 片段放在上述本地宿主中使用：`boot` 是从自己托管子进程首行解析出的握手字典，不是用户填写的凭据，也不要打印它。示例只查询状态，不启动／停止采集，不读取聊天正文：

```python
import json
from urllib.request import Request, build_opener, ProxyHandler

client = build_opener(ProxyHandler({}))
base, token = boot["url"], boot["token"]

def request(path, payload=None):
    headers = {"X-Capture-Token": token, "Origin": base}
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")
    with client.open(Request(base + path, data=data, headers=headers),
                     timeout=15) as response:
        return json.load(response)

state = request("/api/product")
print(json.dumps({"mode": state["product"]["mode"],
                  "watching": state["watching"], "busy": state["busy"]}))
```

获得写操作授权后，同一个 `request` 可提交 `{"action": "backup_pair"}` 等任务对象，再通过 `/api/jobs` 查询返回的任务 ID。不能只收到 ID 就向用户宣称备份或恢复成功。完整的无界面合成流程见 `scripts/smoke-portable.py`，它覆盖采集、停采补采、修订、备份、实际恢复、离线阅读及附件导出；这是测试脚本，不是连接用户正式档案的启动器。

CLI 帮助可在没有 GUI 的情况下查看：

```powershell
.\app\backend-dist\CaptureNextCore\CaptureNextCore.exe --cli --help
```

底层 CLI 命令可用于离线维护或隔离状态，但不保证每个命令都是产品成套流程。已有产品后台时，应使用上述产品队列，不通过直接修改 SQLite、跳过锁或混用旧备份来达成任务。

## 不占前台的边界与隐私

- 后台检索、解码、导出到文件、备份及核验无需前台；真正播放声音、打开外部应用、扫码／手机确认可能仍需用户交互。这些不是后台 API 自动授予的权限。
- 开机启动及通知设置可经接口保存，但 Windows 启动项注册和托盘通知由桌面壳完成；纯后台宿主不能仅凭“设置已保存”宣称系统启动项已生效。
- 工具不内置云端上传，但如果所选 Agent 把查询到的正文或附件交给云端模型，这属于额外数据外发。应让用户知情选择，尽量只传任务所需的最少内容，不能承诺“使用任何 Agent 仍绝不外发”。
- 密钥和会话 token 不应发送到聊天、公开 Issue、命令行参数、URL 或日志。首次配置传 keyring 文件路径而非真实密钥值；文件本身仍按敏感材料保管。
- 未支持媒体、来源不可用、手机未同步历史等原有限制不会因使用 Agent 消失。恢复接管只在恢复模式按既有材料与确认要求执行，不自动登录微信或覆盖原始来源。
