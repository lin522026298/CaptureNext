# 配置与密钥

首次配置只读使用你指定的源目录和 keyring，在安装目录的 `archives/wechat-next/state` 新建独立状态。相同账号使用稳定别名，不用昵称作身份；不同电脑使用不同来源别名。已有状态拒绝覆盖。

原始 keyring 必须放在被监控的微信账号／附件目录**之外**，且不能是硬链接或符号链接；否则可能把它误当附件进入内容库。初始化会在写入前拒绝这种布局，不会自动移动你的文件。其他图片密钥、凭证或私人恢复材料也不要放进被监控附件树。备份中的“包含密钥”开关控制程序受限目录内的数据库 keyring，不可能识别聊天文本或任意附件本身是否包含其他秘密。

keyring 顶层为 `databases` 数组；每条包括：

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `relative_path` | 字符串 | 相对于 `db_storage` 的数据库路径，例如 `message/message_0.db` |
| `verified` | 布尔 | 已对该数据库验证的 key 材料标记；采集仍独立验证每页 |
| `raw_encryption_key_hex` | 字符串 | 32 字节原始 AES 数据库 key 的 64 位十六进制表示，不是密码、不是 DLL 算法常量 |

不在公开文件提供可误认为真实凭证的完整 keyring。初始化会检查类型、条目唯一、相对路径和 key 长度；真正采集时认证所有主库页及有效 WAL，认证失败不会当成成功。

高级用户可不用交互脚本：

```powershell
$db = Read-Host '本机 db_storage 目录'
$keyring = Read-Host '本地 keyring JSON 路径'
$alias = Read-Host '稳定账号别名'
$source = Read-Host '当前来源别名'
.\app\backend-dist\CaptureNextCore\CaptureNextCore.exe --configure --root (Get-Location).Path --database-root $db --keyring $keyring --account-alias $alias --source-id $source
```

必要时加 `--self-username` 指定来源中已验证的原生自身身份。选择标准 `db_storage` 目录时，附件来源默认设为其所属账号目录，扫描排除数据库，消息与附件各走独立认证数据流；也可用 `--asset-root` 明确选择账号内的附件子目录。所有值只存在本机配置中，不写公开发布记录。

只读取你有权访问的数据。取钥工具通过精确 DLL SHA-256 选择适配，仅已验证 `4.1.12.26` 和 `4.1.15.13` 的特定构建；同一版本号的其他构建也可能拒绝。它不注入、不打补丁、不绕过登录，且需要明确指定 PID、当前主机名及先前冻结的本机来源 ZIP。使用帮助确认参数后再操作，不要将资源限额误认为消息采集上限。

源文件不可用或微信退出时保留已归档内容，后续重连执行核验补采。未知格式、缺失 key、附件未完成、备份失败是不同状态；不看到总览错误不等于所有附件都可查看。
