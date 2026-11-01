# 第三方组件与许可

CaptureNext 自有源码依据 GNU GPL v3.0 发布；各组件仍保留自身许可证。发布包的 `app/dependency-notices/` 保存安装版本和许可原文，WebView2 SDK 单独保留 Microsoft 许可。Python 运行库许可随便携后台保留。

| 组件 | 用途 | 许可／来源 |
| --- | --- | --- |
| Python 3.11 | 嵌入后台运行时 | PSF，https://www.python.org/ |
| cryptography | 页加密／认证 | Apache-2.0 或 BSD-3-Clause，https://github.com/pyca/cryptography |
| zstandard | WCDB 内容解压 | BSD-3-Clause，https://github.com/indygreg/python-zstandard |
| pycryptodome | 图片解码 | BSD／Public Domain，https://github.com/Legrandin/pycryptodome |
| psutil | 本机进程与资源观测 | BSD-3-Clause，https://github.com/giampaolo/psutil |
| pilk 0.2.4 | SILK 语音编解码 | GPLv3，https://github.com/foyoux/pilk |
| defusedxml | 非信任 XML 解析防护 | PSF，https://github.com/tiran/defusedxml |
| Pillow | 图片解码与预览 | MIT-CMU，https://github.com/python-pillow/Pillow |
| cffi／pycparser | cryptography 配套 | MIT／BSD，许可随包 |
| Microsoft.Web.WebView2 1.0.3719.77 | Windows 内嵌查看器 | Microsoft SDK 分发许可，https://www.nuget.org/packages/Microsoft.Web.WebView2/1.0.3719.77 |
| PyInstaller | 构建与 bootloader | GPLv2-or-later 加 bootloader 分发例外，https://pyinstaller.org/ |

所有第三方组件未作本地修改。便携包对应源码包括本仓库版本、固定依赖清单和构建脚本；发行版另附 `third-party-sources.zip`，保留需要的上游对应源码与其许可／来源清单，不以一个可能失效的链接代替源码材料。

SILK 实现还包含上游 codec 的许可及专利提示，保留原文；不提供专利授权保证。WebView2 Runtime 不打包到便携 ZIP，用户从 Microsoft 官方安装 Evergreen Runtime；SDK 的受许可可分发 DLL 随程序提供。微信客户端／腾讯 DLL、任何聊天材料和用户 key 不随程序分发。

开发测试依赖 FastAPI、Starlette、uvicorn、httpx 只用于遗留控制台与合成测试；日常新版产品的 HTTP 服务使用标准库，不需要暴露 ASGI 服务。不要将本项目托盘服务当公网服务器部署。
