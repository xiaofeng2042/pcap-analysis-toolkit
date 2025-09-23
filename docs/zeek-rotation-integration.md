# Zeek日志轮转与现有工作流集成指南

## 概述

本文档说明如何将Zeek内置日志轮转功能与现有的 `scripts/rotate-mail-stats.sh` 工作流集成，实现完整的日志管理和归档解决方案。

## Zeek内置轮转配置

### 当前配置

在 `mail-activity-json.zeek` 中已启用以下轮转设置：

```zeek
# Zeek内置日志轮转配置
redef Log::default_rotation_interval = 3600secs;   # 每小时轮转一次
redef Log::default_rotation_postprocessor_cmd = "echo 'Log rotated: %s' >&2";  # 轮转后处理命令
```

### 轮转行为

- **轮转间隔**: 每小时（3600秒）
- **文件命名**: Zeek自动生成时间戳格式的文件名
  - 例如: `mail_activity.log` → `mail_activity.2025-09-23-14-35-31.log`
- **轮转位置**: 与活动日志文件相同目录
- **活动文件**: 继续使用原始文件名，Web UI可持续监控

## 与rotate-mail-stats.sh工作流集成

### 集成策略

现有的 `rotate-mail-stats.sh` 主要处理统计数据文件 (`mail_stats_state.tsv`)，而Zeek轮转处理原始日志文件。两者可以协同工作：

#### 1. 分层归档策略

```bash
# 日志文件层次结构
output/
├── live/                    # 实时监控输出
│   ├── mail_activity.log    # 当前活动日志（Web UI监控）
│   ├── mail_activity.2025-09-23-14-*.log  # Zeek轮转的历史日志
│   └── smtp.log             # Zeek内置SMTP日志
├── state/                   # 统计状态文件
│   └── mail_stats_state.tsv # rotate-mail-stats.sh处理的统计数据
└── archives/                # 长期归档
    ├── 2025-08/             # 按月归档的统计数据
    └── logs/                # 压缩的原始日志文件
```

#### 2. Cron作业集成

创建综合的cron作业来处理两种类型的轮转：

```bash
# /etc/crontab 或 crontab -e
# 每小时压缩Zeek轮转的日志文件
0 * * * * /path/to/scripts/compress-zeek-logs.sh

# 每日运行统计数据轮转
0 2 * * * /path/to/scripts/rotate-mail-stats.sh daily

# 每月归档和清理
0 3 1 * * /path/to/scripts/rotate-mail-stats.sh monthly
```

### 扩展脚本示例

#### compress-zeek-logs.sh

创建一个新脚本来处理Zeek轮转的日志文件：

```bash
#!/bin/bash
# compress-zeek-logs.sh - 压缩和归档Zeek轮转的日志文件

PROJECT_DIR="/path/to/mail-monitoring"
LOG_DIR="$PROJECT_DIR/output/live"
ARCHIVE_DIR="$PROJECT_DIR/output/archives/logs"

# 创建归档目录
mkdir -p "$ARCHIVE_DIR"

# 查找并压缩1小时前的轮转日志文件
find "$LOG_DIR" -name "*.log.*" -type f -mmin +60 | while read -r logfile; do
    if [[ ! "$logfile" =~ \.gz$ ]]; then
        echo "压缩日志文件: $logfile"
        gzip "$logfile"
        
        # 可选：移动到归档目录
        # mv "$logfile.gz" "$ARCHIVE_DIR/"
    fi
done

# 清理超过30天的压缩日志
find "$LOG_DIR" -name "*.log.*.gz" -type f -mtime +30 -delete
find "$ARCHIVE_DIR" -name "*.log.*.gz" -type f -mtime +90 -delete
```

#### 修改rotate-mail-stats.sh

在现有的 `rotate-mail-stats.sh` 中添加日志文件处理功能：

```bash
# 在rotate-mail-stats.sh中添加新函数
archive_zeek_logs() {
    local target_month="$1"
    local dry_run="$2"
    
    log_info "归档Zeek日志文件: $target_month"
    
    local log_pattern="$PROJECT_DIR/output/live/*.log.$target_month-*.gz"
    local archive_dir="$PROJECT_DIR/output/archives/logs/$target_month"
    
    if [ "$dry_run" = "true" ]; then
        log_info "[DRY RUN] 将移动匹配文件: $log_pattern"
        log_info "[DRY RUN] 目标目录: $archive_dir"
        return 0
    fi
    
    mkdir -p "$archive_dir"
    
    # 移动压缩的日志文件到月度归档目录
    if ls $log_pattern 1> /dev/null 2>&1; then
        mv $log_pattern "$archive_dir/"
        log_success "Zeek日志文件已归档到: $archive_dir"
    else
        log_info "未找到需要归档的Zeek日志文件"
    fi
}

# 在monthly rotation函数中调用
rotate_monthly() {
    local dry_run="$1"
    local force="$2"
    
    # ... 现有的统计数据轮转逻辑 ...
    
    # 添加Zeek日志归档
    archive_zeek_logs "$prev_month" "$dry_run"
}
```

### 轮转后处理命令

可以自定义Zeek的轮转后处理命令来触发额外操作：

```zeek
# 在mail-activity-json.zeek中
redef Log::default_rotation_postprocessor_cmd = "/path/to/scripts/post-rotation-handler.sh";
```

`post-rotation-handler.sh` 示例：

```bash
#!/bin/bash
# post-rotation-handler.sh - Zeek轮转后处理

ROTATED_FILE="$1"  # Zeek传递的轮转文件路径

# 记录轮转事件
echo "$(date): 日志文件已轮转: $ROTATED_FILE" >> /var/log/zeek-rotation.log

# 可选：立即压缩
if [[ "$ROTATED_FILE" =~ \.log\. ]] && [[ ! "$ROTATED_FILE" =~ \.gz$ ]]; then
    gzip "$ROTATED_FILE"
fi

# 可选：发送通知
# echo "Zeek日志轮转: $(basename $ROTATED_FILE)" | mail -s "日志轮转通知" admin@example.com
```

## 监控和维护

### 日志空间监控

```bash
# 检查日志目录空间使用
du -sh /path/to/output/live/
du -sh /path/to/output/archives/

# 监控轮转文件数量
ls -1 /path/to/output/live/*.log.* | wc -l
```

### 验证轮转功能

```bash
# 检查Zeek轮转是否正常工作
ls -lt /path/to/output/live/mail_activity.log*

# 验证压缩和归档
find /path/to/output -name "*.log.*.gz" -ls

# 检查统计数据轮转
./scripts/rotate-mail-stats.sh status
```

## 最佳实践

### 1. 保留策略

- **活动日志**: 保持当前文件供Web UI监控
- **轮转日志**: 本地保留24-48小时后压缩
- **压缩日志**: 保留30天后移动到归档
- **归档日志**: 根据合规要求保留90天-1年

### 2. 性能考虑

- 使用压缩减少存储空间（通常可减少80-90%）
- 在低峰时段进行归档操作
- 监控磁盘I/O避免影响实时监控

### 3. 故障恢复

- 定期备份关键配置文件
- 保留足够的日志用于问题诊断
- 实施日志完整性检查

## 总结

通过将Zeek内置轮转与现有的 `rotate-mail-stats.sh` 工作流集成：

1. **Zeek处理**: 原始日志文件的实时轮转
2. **rotate-mail-stats.sh处理**: 统计数据的定期归档
3. **协同工作**: 完整的日志生命周期管理

这种分层方法确保了：
- Web UI持续监控活动日志
- 历史数据得到适当归档
- 存储空间得到有效管理
- 符合数据保留要求