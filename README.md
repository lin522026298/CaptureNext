# CaptureNext

Windows 本地微信采集、联合归档、去重、聊天查看及成套备份恢复工具。托盘、独立窗口和可选 WebUI 共用一个后台，不向云端上传聊天内容。

> 适用边界：Windows x64、微信 Windows 4.x 数据格式，以及你本人已获授权的本地数据库和对应密钥。不是微信官方工具，不保证未来所有客户端版本。只采集电脑实际落盘且可认证的消息；电脑退出期间未同步回本机的消息无法凭空补回。手机全历史及原生 3.x 加密库不在自动采集范围内。

## 下载并使用

1. 从 [Releases](https://github.com/lin522026298/CaptureNext/releases) 下载 `CaptureNext-*-windows-x64.zip`，完整解压到本地可写目录，不要解压到微信数据目录。不要从 ZIP 内直接运行。
2. Windows 10/11 x64、.NET Framework 4.8 与 [Microsoft WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/) 是桌面前提；便携包已包含 Python 后台，不需要安装 Python。程序尚未代码签名，Windows 可能显示未知发布者，请先核对 SHA-256。
3. 首次运行 `Configure-CaptureNext.ps1`：输入本机 `db_storage` 目录、已授权 keyring JSON 的路径、稳定账号别名和当前电脑来源别名。脚本不索取密码，不自动登录、不自动读取微信进程内存，也不覆盖已有档案。
4. 运行 `Start-CaptureNext.ps1`；以后可加 `-Tray` 静默进入托盘。设置中独立选择登录后自启动、自动采集、备份计划、是否包含密钥和深度核验计划。

如文件的系统下载标记阻止运行，先检查脚本内容和校验和，再通过文件属性解除该下载文件的锁定；不要全局放宽 PowerShell 执行策略。也可以在 PowerShell 当前窗口执行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Configure-CaptureNext.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-CaptureNext.ps1
```

这里只对这次子进程使用执行策略参数，不修改系统策略。初次配置不启动采集，正式启动后会读取、认证并归档整个已配置本地来源，不截断历史。大量历史或附件的首次处理可能较久，分项状态会显示未完成事项。

## 我还没有数据库密钥

密钥不在下载包或仓库中。你必须使用自己数据对应的材料；不要把 keyring 或聊天库上传到 Issue、网盘示例或 Git。输入格式见 [配置与密钥](docs/configuration.md)。仓库包含显式 PID、主机名、DLL 哈希锁定的只读取钥工具，但只适配已经验证的两个 Windows 客户端构建，不能把未知版本强行套入偏移。

```powershell
.\app\backend-dist\CaptureNextCore\CaptureNextCore.exe --key-probe --help
```

取钥需你单独明确选择目标与冻结来源；程序日常采集不执行此操作。拿不到可验证密钥时请停止初始化，不要降级、清理或覆盖微信数据。

## 日常阅读与故障恢复

- 会话列表、可读联系人名称、日期／类型／发送者筛选、搜索及前后文跳转。
- 消息详情显示来源、观察版本、修订、冲突及重复判定依据；昵称相同不会自动认作同一身份。
- 图片、语音、视频和文件按可验证关联使用；未知关联、候选、文件缺失和暂不支持解码分别展示，不以时间相近猜配。某些格式需要额外本地图片密钥或仍不支持。
- 自动采集后自动增量归并及索引。微信重新上线后补采的是本机新落盘内容，不承诺恢复微信未再同步的远端历史。
- 备份默认保留最近两个成功恢复点，手动固定点单独保留；新备份成功验证后才回收无引用块。密钥备份默认关闭，只有显式开启才包含。
- 正式档案损坏时，使用 `Start-CaptureNext.ps1 -Recovery`，先恢复到全新副本，再只读查看；恢复接管是另一项显式操作，不自动覆盖正式状态或登录微信。详见 [恢复指南](docs/recovery.md)。

关闭窗口回托盘；关闭 WebUI 不停止采集。退出请使用托盘“退出（安全收尾）”，不要强行杀进程。复制或移动整个安装目录前先安全退出；启用自启动后不要直接移动程序而不重新设置启动项。

## 从源码构建

使用全新目录和 **64 位 Python 3.11**；无需本项目作者的开发环境、档案、SDK 或微信 DLL：

```powershell
git clone https://github.com/lin522026298/CaptureNext.git
cd CaptureNext
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-portable.ps1
.\.venv\Scripts\python.exe -m unittest discover -s wechat_capture_next/tests -q
```

脚本建立目录内 `.venv`，从 PyPI 安装固定直接依赖，从 NuGet 下载固定 WebView2 SDK 并核对 SHA-256，输出 `app/`；不会修改已有安装，输出存在时拒绝覆盖。第三方许可及构建说明见 [THIRD_PARTY.md](THIRD_PARTY.md)。完整环境锁定和发布验收见 [发布检查](docs/release-check.md)。

源码 ZIP 不是已经编译的便携包。开发中的旧启动器和低层诊断模块仅用于兼容／维护，不是普通用户入口；日常只使用根目录入口，不要同时另启 CLI 写者。

## 隐私与许可

自有源码采用 [GNU GPL v3.0](LICENSE)，第三方组件保留各自许可。发布包附对应源码材料和依赖许可，不含腾讯客户端 DLL。

仓库只含程序、合成测试及通用说明，不含个人聊天、附件、账号映射、档案、真实 keyring、本地配置或开发 Git 历史。代码中客户端算法常量、DLL 适配哈希和合成测试 key 不是任何用户的实际密钥。

本地档案和可选含密钥备份本身是敏感明文材料，请使用访问控制、磁盘加密及独立可靠介质。备份放在同一磁盘不能代替防磁盘损坏的异盘备份。安全报告方式见 [SECURITY.md](SECURITY.md)。
