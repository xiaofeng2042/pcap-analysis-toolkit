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

## 许可证

本项目仅供学习和研究使用。