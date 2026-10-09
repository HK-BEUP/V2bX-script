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

## 菜单 15：重新配置

管理菜单 **15**、`v2bx generate` 或 `v2bx init` 可手动生成或重新配置 VLESS/Xray 节点。
面板和节点编号可回车保留；同一面板只有一个现有 API Key 时，隐藏输入处回车可保留该密钥。
向导显示保留、新增和移除的节点数；最终输入 `YES` 才应用。

- 服务运行时：备份，等待原进程正常退出，应用配置并启动；失败尝试恢复原配置和运行状态。
- 服务已停止时：只保存，不启动、不更改开机自启。参数不变或取消时不保存、不重启。
- 全局设置及同面板同编号节点的选项保持；新身份使用新装默认配置。未列出的旧节点移出配置，但不删除其 journal。
- DNS/路由文件、证书、程序和 journal 不改。TransferAccounting 安装更换节点身份、自定义服务或外置 Include 配置须另行核对。
- 备份位于 `/etc/.backups/V2bX/reconfigure-*/`，含原配置、SHA-256 和 `transaction.json`。出现并发修改时不覆盖，应按记录人工处理；回滚前先比对现有 SHA。

重新配置运行中的实例会短暂中断本机全部节点；进程/监听验证通过后仍需实际客户端和面板入账验证。
此入口与安装器的首次初始化分开，自动安装仍拒绝覆盖已有节点配置。

已有服务器必须更新**配套的管理脚本和 initconfig.py**才获得此修复；仅刷新 GitHub 页面或再次安装相同二进制不会更新脚本。
使用新版完整发行包时仍按已有升级流程确认，不建议从原版覆盖单个脚本。
