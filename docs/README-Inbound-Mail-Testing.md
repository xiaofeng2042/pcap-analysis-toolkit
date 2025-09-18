# 收信测试完整指南

本文档提供了使用 GreenMail 和 Zeek 进行邮件收信测试的完整解决方案。

## 概述

收信测试系统包含以下组件：
- **GreenMail**: 本地邮件服务器，支持 SMTP、POP3、IMAP 协议
- **Zeek**: 网络流量分析器，监控邮件协议活动
- **测试脚本**: 自动化邮件发送和接收验证

## 系统架构

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   邮件客户端     │    │   GreenMail     │    │   Zeek 监控     │
│   (swaks/telnet)│───▶│   邮件服务器     │───▶│   流量分析      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   测试验证      │
                       │   (POP3/IMAP)   │
                       └─────────────────┘
```

## 快速开始

### 1. 启动收信监控系统

```bash
# 启动完整的收信监控系统
./scripts/start-inbound-mail-monitor.sh
```

这个命令会：
- 启动 GreenMail Docker 容器
- 启动 Zeek 监控（监听回环接口）
- 创建日志目录
- 显示系统状态

### 2. 发送测试邮件

```bash
# 交互式邮件发送测试
./scripts/test-mail-delivery.sh
```

支持的测试类型：
- 简单文本邮件
- 带附件邮件
- HTML 格式邮件
- 批量邮件发送

### 3. 验证邮件接收

```bash
# 邮件接收验证测试
./scripts/test-mail-retrieval.sh
```

支持的协议测试：
- POP3 协议测试
- IMAP 协议测试
- 邮箱状态检查

### 4. 停止监控系统

```bash
# 停止所有服务
./scripts/stop-inbound-mail-monitor.sh
```

## 服务端口配置

### GreenMail 端口映射

| 协议 | 端口 | 加密 | 说明 |
|------|------|------|------|
| SMTP | 3025 | 无 | 邮件发送 |
| SMTPS | 3465 | SSL | 加密邮件发送 |
| POP3 | 3110 | 无 | 邮件接收 |
| POP3S | 3995 | SSL | 加密邮件接收 |
| IMAP | 3143 | 无 | 邮件访问 |
| IMAPS | 3993 | SSL | 加密邮件访问 |

### 测试账号

| 用户名 | 密码 | 说明 |
|--------|------|------|
| test@local | secret | 主要测试账号 |
| admin@local | admin123 | 管理员测试账号 |

## 手动测试方法

### SMTP 邮件发送

使用 swaks 发送邮件：

```bash
# 发送简单邮件
swaks --to test@local --from demo@local --server 127.0.0.1:3025 \
      --data 'Subject: Test Mail

Hello, this is a test message.'

# 发送带附件邮件
swaks --to test@local --from demo@local --server 127.0.0.1:3025 \
      --attach /path/to/file.txt \
      --data 'Subject: Mail with Attachment

This mail contains an attachment.'
```

### POP3 邮件接收测试

使用 telnet 连接 POP3：

```bash
telnet 127.0.0.1 3110
```

POP3 命令序列：
```
USER test@local
PASS secret
STAT                # 查看邮箱状态
LIST                # 列出邮件
RETR 1              # 获取第一封邮件
QUIT                # 退出
```

### IMAP 邮件访问测试

使用 telnet 连接 IMAP：

```bash
telnet 127.0.0.1 3143
```

IMAP 命令序列：
```
A001 LOGIN test@local secret
A002 SELECT INBOX
A003 FETCH 1 BODY[]         # 获取第一封邮件内容
A004 LOGOUT
```

## Zeek 监控配置

### 监控脚本

系统使用以下 Zeek 脚本：

1. **site-mail-ports.zeek**: 邮件端口注册
2. **mail-inbound-monitor.zeek**: 收信活动监控

### 监控端口

Zeek 监控以下端口的流量：
```
port 3025 or port 3110 or port 3143 or port 3465 or port 3993 or port 3995
```

### 日志文件

监控产生的日志文件：

| 文件 | 内容 |
|------|------|
| conn.log | 连接记录 |
| smtp.log | SMTP 协议日志 |
| imap.log | IMAP 协议日志 |
| pop3.log | POP3 协议日志 |
| mail_inbound.log | 自定义收信监控日志 |

## 高级配置

### SSL/TLS 测试

对于加密连接测试：

```bash
# SMTPS 测试
openssl s_client -connect 127.0.0.1:3465

# IMAPS 测试
openssl s_client -connect 127.0.0.1:3993

# POP3S 测试
openssl s_client -connect 127.0.0.1:3995
```

### 自定义 GreenMail 配置

编辑 `docker/greenmail/docker-compose.yml` 来修改：
- 用户账号
- 端口映射
- 环境变量

### 扩展 Zeek 监控

修改 `zeek-scripts/mail-inbound-monitor.zeek` 来：
- 添加自定义事件处理
- 扩展日志字段
- 增加协议分析

## 故障排除

### 常见问题

1. **Docker 服务启动失败**
   ```bash
   # 检查 Docker 状态
   docker info
   
   # 查看容器日志
   docker logs greenmail-server
   ```

2. **Zeek 监控无数据**
   ```bash
   # 检查网络接口
   ifconfig lo0
   
   # 验证端口监听
   netstat -an | grep 3025
   ```

3. **邮件发送失败**
   ```bash
   # 测试端口连通性
   nc -z 127.0.0.1 3025
   
   # 检查防火墙设置
   ```

### 日志分析

查看实时日志：
```bash
# 查看最新日志目录
ls -la logs/latest-inbound/

# 实时监控连接日志
tail -f logs/latest-inbound/conn.log

# 查看邮件协议日志
tail -f logs/latest-inbound/mail_inbound.log
```

## 性能优化

### 批量测试

对于大量邮件测试：

1. 调整 GreenMail 内存限制
2. 增加 Zeek 缓冲区大小
3. 使用 SSD 存储日志

### 监控优化

1. 限制日志文件大小
2. 定期清理旧日志
3. 使用日志轮转

## 扩展应用

### 集成到 CI/CD

```yaml
# GitHub Actions 示例
- name: Start Mail Testing
  run: ./scripts/start-inbound-mail-monitor.sh

- name: Run Mail Tests
  run: |
    ./scripts/test-mail-delivery.sh
    ./scripts/test-mail-retrieval.sh

- name: Analyze Results
  run: ./scripts/analyze-mail-logs.sh
```

### 自动化测试

创建自动化测试脚本：
```bash
#!/bin/bash
# 自动化收信测试流程
./scripts/start-inbound-mail-monitor.sh
sleep 10
./scripts/test-mail-delivery.sh
./scripts/test-mail-retrieval.sh
./scripts/stop-inbound-mail-monitor.sh
```

## 参考资料

- [GreenMail 官方文档](https://greenmail-mail-test.github.io/greenmail/)
- [Zeek 网络安全监控](https://zeek.org/)
- [SMTP 协议规范 RFC 5321](https://tools.ietf.org/html/rfc5321)
- [IMAP 协议规范 RFC 3501](https://tools.ietf.org/html/rfc3501)
- [POP3 协议规范 RFC 1939](https://tools.ietf.org/html/rfc1939)

## 许可证

本项目遵循 MIT 许可证。详见 LICENSE 文件。