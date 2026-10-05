# HK-BEUP V2bX 一键安装

支持 Linux/systemd 和 Alpine/OpenRC、x86_64 和 aarch64；需要 root、Python 3（含 SSL），下载入口使用 wget 或 curl。

```bash
wget -N https://raw.githubusercontent.com/HK-BEUP/V2bX-script/master/install.sh && bash install.sh
```

填写 HTTPS 面板域名、API Key（隐藏输入）、节点编号，确认后完成配置、启动和开机自启。
面板节点使用 VLESS + TCP + REALITY + Vision，并支持 HK-BEUP 旧队列回执。
新装默认 LegacyAccounting，使用旧 Redis/Horizon 的处理体系，包含持久化重试与尾流保护。节点日志默认关闭。

已有安装执行本命令时，保留配置、证书、journal 和原运行状态，不会改写计量模式。
备份位于 /usr/local/.backups/V2bX/。等待尾流入账可能跨一个分钟周期，请勿强杀或删除 journal。

手动配置可用 `v2bx init`；管理用 `v2bx`。启动检查仅确认进程与 TCP 监听，实际流量入账以面板为准。
源代码及构建说明：[HK-BEUP/V2bX](https://github.com/HK-BEUP/V2bX)。

同二进制重复安装直接提示并跳过，不停止服务；不同版本需确认后才升级。
OpenRC 会保留已停止状态；升级运行中的原版标准服务时，备份并补齐无强杀等待及日志关闭的服务脚本。自定义服务或 conf.d 覆盖配置需单独核对。
Alpine 全新环境先使用系统 apk 安装 bash、python3、ca-certificates、wget；不要为安装 V2bX 改用 systemd。
