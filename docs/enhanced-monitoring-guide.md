# 增强版邮件监控指南

## 概述

增强版邮件监控系统扩展了原有的SMTP监控功能，现在可以同时监控邮件的发送和接收流量：

- **SMTP协议** (发送邮件): 端口 25, 465, 587, 2525
- **IMAP协议** (接收邮件): 端口 143 (IMAP), 993 (IMAPS)
- **POP3协议** (接收邮件): 端口 110 (POP3), 995 (POP3S)

## 快速开始

### 1. 使用增强版启动脚本

```bash
# 启动增强版邮件监控
sudo ./scripts/start-enhanced-mail-monitor.sh
```

### 2. 使用原有脚本的新选项

```bash
# 启动原有脚本，选择"完整邮件监控"选项
sudo ./scripts/start-smtp-monitor.sh
# 然后选择选项 2: 完整邮件监控 (SMTP发送 + IMAP/POP3接收)
```

## 监控模式说明

### 基础SMTP监控 (选项1)
- 只监控SMTP发送端口
- 使用 `simple-smtp-monitor.zeek` 脚本
- 生成 `smtp.log` 文件

### 完整邮件监控 (选项2) ⭐ 推荐
- 监控所有邮件协议端口
- 使用 `enhanced-mail-monitor.zeek` 脚本
- 生成多个日志文件：
  - `smtp.log` - SMTP发送记录
  - `imap.log` - IMAP接收记录
  - `pop3.log` - POP3接收记录
  - `ssl.log` - SSL/TLS连接记录
  - `mail_stats.log` - 邮件统计信息

### 增强监控 (选项3)
- SMTP端口 + DNS端口53
- 用于深度包检测

### 自定义过滤器 (选项4)
- 允许用户输入自定义BPF过滤规则
- 适合特殊监控需求

### 无过滤器 (选项5)
- 监控所有网络流量
- 使用增强版脚本进行协议分析

## 日志文件说明

### smtp.log
记录SMTP邮件发送活动：
```
ts          uid     id.orig_h    id.orig_p  id.resp_h    id.resp_p  trans_depth  helo      mailfrom           rcptto             date              from               to                 reply_to  msg_id  in_reply_to  subject  x_originating_ip  first_received  second_received  last_reply  path  user_agent  tls  fuids  is_webmail
```

### imap.log
记录IMAP邮件接收活动：
```
ts          uid     id.orig_h    id.orig_p  id.resp_h    id.resp_p  command  arg  status  username
```

### pop3.log
记录POP3邮件接收活动：
```
ts          uid     id.orig_h    id.orig_p  id.resp_h    id.resp_p  command  arg  status  username
```

### mail_stats.log
每5分钟生成的邮件统计信息：
```
timestamp                    smtp_connections  imap_connections  pop3_connections  ssl_connections  total_connections
2024-09-17T14:45:00.000000Z  5                 12                3                 15               35
```

## 测试监控功能

### 测试SMTP发送
```bash
# 使用telnet测试SMTP连接
telnet smtp.gmail.com 587
```

### 测试IMAP接收
```bash
# 使用邮件客户端或telnet测试IMAP
telnet imap.gmail.com 993
```

### 测试POP3接收
```bash
# 使用邮件客户端或telnet测试POP3
telnet pop.gmail.com 995
```

## 停止监控

### 使用专用停止脚本
```bash
# 停止增强版监控
./scripts/stop-enhanced-monitor.sh

# 或停止原有监控
./scripts/stop-monitor.sh
```

### 手动停止
```bash
# 查找并停止zeek进程
sudo pkill -f "zeek.*enhanced-mail-monitor"
```

## 故障排除

### 1. 权限问题
确保以root权限运行：
```bash
sudo ./scripts/start-enhanced-mail-monitor.sh
```

### 2. 网卡问题
检查可用网卡：
```bash
ifconfig | grep -E "^[a-z]"
```

### 3. 端口冲突
检查端口占用：
```bash
sudo lsof -i :993  # 检查IMAPS端口
sudo lsof -i :995  # 检查POP3S端口
```

### 4. 日志文件为空
- 确认选择了正确的监控模式
- 检查是否有实际的邮件流量
- 验证BPF过滤器是否正确

### 5. Zeek脚本错误
检查Zeek脚本语法：
```bash
zeek -T zeek-scripts/enhanced-mail-monitor.zeek
```

## 配置文件

### BPF过滤器配置
文件：`configs/enhanced-mail-filter.bpf`
```
port 25 or port 465 or port 587 or port 2525 or port 143 or port 993 or port 110 or port 995
```

### Zeek脚本配置
主脚本：`zeek-scripts/enhanced-mail-monitor.zeek`
- 加载SMTP、IMAP、POP3、SSL协议模块
- 定义事件处理函数
- 生成统计信息

## 性能优化建议

1. **选择合适的网卡**：使用活跃的网卡进行监控
2. **合理的过滤规则**：避免监控不必要的流量
3. **定期清理日志**：防止日志文件过大
4. **监控系统资源**：确保有足够的CPU和内存

## 安全注意事项

1. **权限管理**：只在必要时使用root权限
2. **日志保护**：确保日志文件的访问权限
3. **网络隐私**：遵守相关法律法规
4. **数据加密**：注意SSL/TLS流量的处理