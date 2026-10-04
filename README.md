# HK-BEUP V2bX 一键安装

支持 Linux/systemd、x86_64 和 aarch64；需要 root、curl 和 Python 3。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/HK-BEUP/V2bX-script/master/install.sh)
```

填写 HTTPS 面板域名、API Key（隐藏输入）、节点编号，确认后完成配置、启动和开机自启。
面板节点使用 VLESS + TCP + REALITY + Vision，并支持 HK-BEUP 旧队列回执。
新装默认 LegacyAccounting，使用旧 Redis/Horizon 的处理体系，包含持久化重试与尾流保护。节点日志默认关闭。

已有安装执行本命令时，保留配置、证书、journal 和原运行状态，不会改写计量模式。
备份位于 /usr/local/.backups/V2bX/。等待尾流入账可能跨一个分钟周期，请勿强杀或删除 journal。

手动配置可用 `v2bx init`；管理用 `v2bx`。启动检查仅确认进程与 TCP 监听，实际流量入账以面板为准。
源代码及构建说明：[HK-BEUP/V2bX](https://github.com/HK-BEUP/V2bX)。
