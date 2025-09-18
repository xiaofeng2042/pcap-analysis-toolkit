# SMTP 实时监控项目

这是一个基于 Zeek 的 SMTP 实时监控系统，用于监控和分析网络中的 SMTP 流量。

## 项目结构

```
.
├── README.md                    # 项目说明文档
├── .gitignore                   # Git 忽略文件配置
├── scripts/                     # Shell 脚本目录
│   ├── start-smtp-monitor.sh    # SMTP 监控启动脚本
│   └── stop-monitor.sh          # 监控停止脚本（运行时生成）
├── zeek-scripts/                # Zeek 脚本目录
│   ├── simple-smtp-monitor.zeek # 简化版 SMTP 监控脚本
│   └── live-smtp-monitor.zeek   # 完整版 SMTP 监控脚本
├── pcap-samples/                # PCAP 样本文件目录
│   └── *.pcap, *.pcapng         # 网络包捕获文件
├── configs/                     # 配置文件目录
│   └── *.bpf                    # BPF 过滤器配置
├── docs/                        # 文档目录
│   └── README*.md               # 各种说明文档
└── logs/                        # 日志目录
    └── live-logs/               # 实时监控日志
        └── YYYYMMDD_HHMMSS/     # 按时间戳分组的日志
```

## 快速开始

### 1. 启动监控

```bash
cd /Users/fxf/Desktop/123
sudo ./scripts/start-smtp-monitor.sh [网卡名称]
```

默认监控网卡 `en0`，你可以指定其他网卡。

### 2. 选择监控模式

启动时会提示选择监控模式：
- **基础监控**: 只监控标准 SMTP 端口 (25, 465, 587, 2525)
- **增强监控**: 包含深度包检测
- **自定义过滤器**: 使用自定义 BPF 过滤规则
- **无过滤器**: 监控所有网络流量

### 3. 停止监控

```bash
# 使用生成的停止脚本
./scripts/stop-monitor.sh

# 或者手动停止
pkill -f "zeek.*simple-smtp-monitor"
```

## 监控功能

- **SMTP 连接监控**: 实时监控 SMTP 连接建立
- **TLS/SSL 监控**: 监控 STARTTLS 握手过程
- **连接统计**: 定期输出连接统计信息
- **日志记录**: 自动记录所有监控数据到日志文件

## 日志文件

监控日志保存在 `logs/live-logs/YYYYMMDD_HHMMSS/` 目录下：
- `smtp.log`: SMTP 连接日志
- `ssl.log`: SSL/TLS 连接日志
- 其他 Zeek 生成的日志文件

## 系统要求

- macOS 或 Linux 系统
- Zeek 网络分析框架
- root 权限（用于网络监控）

## 注意事项

- 监控需要 root 权限
- 确保指定的网卡存在且可用
- 监控会产生大量日志，注意磁盘空间
- 建议在测试环境中使用

## 故障排除

如果遇到问题，请检查：
1. Zeek 是否正确安装
2. 网卡名称是否正确
3. 是否有足够的权限
4. 防火墙设置是否阻止监控

## 快速验证：邮件发送/接收 JSON 日志

为了验证 Zeek 可以同时捕获发信（SMTP）和收信（POP3）活动，并直接生成 JSON 格式日志，可以使用新增脚本 `zeek-scripts/mail-activity-json.zeek`。

- **离线 SMTP 示例（发信）**
  ```bash
  mkdir -p analysis/mail-activity-smtp
  cd analysis/mail-activity-smtp
  zeek -Cr ../../pcap-samples/smtp.pcap ../../zeek-scripts/mail-activity-json.zeek
  jq 'select(.protocol == "SMTP")' mail_activity.log | head
  ```
  该命令会读取仓库自带的 `smtp.pcap` 样本，并生成 `mail_activity.log`（JSON）。日志中可直接看到 `SMTP_MAIL`、`SMTP_RCPT` 等事件，验证发信流程。

- **本地 POP3 示例（收信）**
  1. 启动 GreenMail 提供测试邮箱：`docker compose -f docker/greenmail/docker-compose.yml up -d`
  2. 另开终端执行：
     ```bash
     mkdir -p analysis/mail-activity-pop3
     cd analysis/mail-activity-pop3
     sudo zeek -i lo0 ../../zeek-scripts/mail-activity-json.zeek "port 3110"
     ```
  3. 在原终端运行 `./scripts/test-mail-retrieval.sh`，选择 POP3 测试（默认连接 3110）。
  Zeek 会实时写入 `analysis/mail-activity-pop3/mail_activity.log`，其中包含 `POP3_USER`、`POP3_RETR` 等事件，证明收信流程同样可被 JSON 记录。

- **日志字段**
  `mail_activity.log` 中关键字段包括：
  - `protocol`: `SMTP` 或 `POP3`
  - `role`: `send`（发信）或 `receive`（收信）
  - `activity`: 具体指令或状态（如 `SMTP_MAIL`, `POP3_REPLY_RETR`）
  - `mail_from` / `rcpt_to` / `user`: 关键邮箱信息
  - `status` / `detail`: 服务器返回码及文本

## 许可证

本项目仅供学习和研究使用。
