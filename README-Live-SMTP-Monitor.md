# 实时SMTP流量监控方案

## 🎯 概述

基于Zeek的实时SMTP流量监控系统，可以实时捕获和分析网络中的SMTP通信，包括STARTTLS加密升级过程。

## 📁 文件说明

### 核心配置文件
- **`live-smtp-monitor.zeek`** - 主监控配置，包含实时统计和事件处理
- **`site-smtp-ports.zeek`** - SMTP端口注册（支持2525等非标准端口）
- **`smtp-starttls-flag.zeek`** - STARTTLS事件检测和标记

### 过滤规则
- **`simple-smtp-filter.bpf`** - 基础SMTP端口过滤（25, 465, 587, 2525）
- **`smtp-filter.bpf`** - 增强过滤，包含深度包检测

### 启动脚本
- **`quick-smtp-monitor.sh`** - 一键快速启动（推荐）
- **`start-smtp-monitor.sh`** - 完整启动脚本，支持多种选项
- **`test-smtp-capture.sh`** - 配置测试脚本

## 🚀 快速开始

### 方法1: 一键启动（推荐）
```bash
sudo ./quick-smtp-monitor.sh
```

### 方法2: 完整启动
```bash
sudo ./start-smtp-monitor.sh en0
```

### 方法3: 手动启动
```bash
sudo zeek -i en0 -f "port 25 or port 465 or port 587 or port 2525" live-smtp-monitor.zeek
```

## 📊 监控功能

### 实时统计
- SMTP连接总数
- STARTTLS尝试次数
- STARTTLS成功次数
- 加密连接数量
- 加密成功率

### 事件检测
- 新SMTP连接建立
- STARTTLS命令发送
- TLS握手成功
- 邮件附件检测

### 日志输出
- **smtp.log** - SMTP协议详细信息
- **ssl.log** - TLS/SSL握手信息
- **notice.log** - STARTTLS事件通知
- **conn.log** - 连接基础信息
- **x509.log** - 证书信息

## 🎛️ 监控选项

启动时可选择不同的监控模式：

1. **基础监控** - 只监控标准SMTP端口
2. **增强监控** - 包含深度包检测
3. **自定义过滤器** - 用户自定义BPF规则
4. **无过滤器** - 监控所有网络流量

## 📈 实时报告

系统每5分钟自动生成统计报告：

```
==================================================
📊 SMTP流量统计 [2024-01-20 15:30:00]
   SMTP连接总数: 5
   STARTTLS尝试: 4
   STARTTLS成功: 4
   加密连接数: 4
   加密成功率: 100.0%
==================================================
```

## 🔍 使用场景

### 1. 邮件服务器监控
```bash
# 监控邮件服务器的SMTP流量
sudo ./quick-smtp-monitor.sh
```

### 2. 安全审计
```bash
# 检查STARTTLS使用情况
sudo ./start-smtp-monitor.sh en0
# 选择模式: 2 (增强监控)
```

### 3. 网络故障排查
```bash
# 监控特定端口
sudo zeek -i en0 -f "port 2525" live-smtp-monitor.zeek
```

## 🛠️ 测试验证

### 配置测试
```bash
./test-smtp-capture.sh
```

### 功能测试
在另一个终端中：
```bash
# 测试SMTP连接
telnet smtp.gmail.com 587

# 发送测试邮件
echo 'Test' | mail -s 'Test Subject' test@example.com
```

### 查看实时日志
```bash
tail -f smtp-live-*/smtp.log
tail -f smtp-live-*/notice.log
```

## 📋 系统要求

- **操作系统**: macOS/Linux
- **权限**: root权限（网络监控需要）
- **依赖**: Zeek网络分析框架
- **网卡**: 有效的网络接口

## 🔧 故障排除

### 常见问题

1. **权限不足**
   ```bash
   # 确保使用sudo运行
   sudo ./quick-smtp-monitor.sh
   ```

2. **网卡不存在**
   ```bash
   # 查看可用网卡
   ifconfig -l
   # 指定正确的网卡
   sudo ./start-smtp-monitor.sh wlan0
   ```

3. **Zeek未安装**
   ```bash
   # macOS安装
   brew install zeek
   
   # Ubuntu安装
   sudo apt-get install zeek
   ```

## 💡 高级用法

### 自定义BPF过滤器
```bash
# 监控特定IP的SMTP流量
sudo zeek -i en0 -f "host 192.168.1.100 and (port 25 or port 587)" live-smtp-monitor.zeek
```

### 长期监控
```bash
# 后台运行
nohup sudo ./quick-smtp-monitor.sh > smtp-monitor.log 2>&1 &
```

### 日志分析
```bash
# 使用之前的分析脚本
python3 smtp-analysis-summary.py
```

## 🔒 安全注意事项

- 监控需要root权限，请确保在安全环境中运行
- 不会解密TLS流量，只分析元数据
- 日志文件可能包含敏感信息，请妥善保管
- 遵守当地法律法规和公司政策

## 🎯 核心优势

1. **实时监控** - 即时发现SMTP通信
2. **STARTTLS检测** - 专门针对加密升级过程
3. **多端口支持** - 支持标准和非标准SMTP端口
4. **灵活过滤** - 多种过滤模式可选
5. **详细日志** - 完整的协议层信息
6. **易于使用** - 一键启动，无需复杂配置

## 📞 停止监控

按 `Ctrl+C` 或使用停止脚本：
```bash
./stop-monitor.sh
```