# 邮件监控项目规则

## 项目概述
本项目使用 Zeek 进行邮件协议（SMTP/POP3）的网络流量监控和分析。所有修改应基于现有配置和脚本进行，避免代码变得混乱。

## 核心原则

### 1. 基于现有配置修改
- **禁止创建重复功能的新文件**
- **优先扩展现有脚本功能**
- **保持项目结构简洁清晰**
- **避免功能分散到多个文件**

### 2. 代码维护规范
- 所有增强功能应集成到 `zeek-scripts/mail-activity-json.zeek` 中
- 删除不再使用的重复脚本文件
- 保持配置参数的一致性和可维护性
- 使用统一的命名规范和代码风格

## 配置规则

### 邮件协议端口配置
基于现有配置，标准化邮件协议端口定义：

```zeek
# SMTP 端口（基于现有配置）
const SMTP_PORTS: set[port] = {
    25/tcp,    # 标准 SMTP
    465/tcp,   # SMTPS (SSL)
    587/tcp,   # SMTP 提交端口
    2525/tcp,  # 备用 SMTP
    1025/tcp,  # 非标准端口
    3025/tcp,  # 测试端口（GreenMail）
    3465/tcp   # 测试 SMTPS
} &redef;

# POP3 端口（基于现有配置）
const POP3_PORTS: set[port] = {
    110/tcp,   # 标准 POP3
    995/tcp,   # POP3S (SSL)
    3110/tcp,  # 测试端口（GreenMail）
    3995/tcp   # 测试 POP3S
} &redef;
```

### 日志记录规则

#### 日志格式标准
- **强制使用 JSON 格式**：`redef LogAscii::use_json = T;`
- **统一日志文件名**：`mail_activity.log`
- **必需字段**：`ts`, `uid`, `id`, `protocol`, `role`, `activity`
- **可选字段**：`subject`, `from_header`, `to_header`, `message_id`, `tls_version`

#### 日志记录规范
```zeek
# 标准日志记录结构
type Info: record {
    # 基础字段（必需）
    ts: time &log;
    uid: string &log;
    id: conn_id &log;
    protocol: string &log;        # "SMTP" 或 "POP3"
    role: string &log;            # "send" 或 "receive"
    activity: string &log;        # 具体活动类型
    
    # 邮件信息字段（可选）
    mail_from: string &log &optional;
    rcpt_to: string &log &optional;
    user: string &log &optional;
    status: string &log &optional;
    detail: string &log &optional;
    
    # 增强字段（可选）
    subject: string &log &optional;
    from_header: string &log &optional;
    to_header: string &log &optional;
    message_id: string &log &optional;
    tls_version: string &log &optional;
    attachment_count: count &log &optional;
};
```

## 监控规则

### 邮件活动分类
基于现有事件处理逻辑，标准化活动分类：

#### SMTP 活动类型
- `SMTP_HELO` / `SMTP_EHLO` - 连接建立
- `SMTP_MAIL` - 发件人设置
- `SMTP_RCPT` - 收件人设置
- `SMTP_DATA` - 邮件内容传输
- `SMTP_STARTTLS` - TLS 加密请求
- `SMTP_CONNECTION_END` - 连接结束

#### POP3 活动类型
- `POP3_USER` - 用户认证
- `POP3_PASS` - 密码认证
- `POP3_RETR` - 邮件检索
- `POP3_CONNECTION_END` - 连接结束

### 统计监控规则
基于现有统计变量，标准化监控指标：

```zeek
# 全局统计变量
global smtp_connections = 0;      # SMTP 连接数
global starttls_attempts = 0;     # STARTTLS 尝试次数
global starttls_success = 0;      # STARTTLS 成功次数
global encrypted_connections = 0;  # 加密连接数

# 统计报告间隔
const report_interval = 30sec &redef;
```

## 安全检测规则

### TLS 加密监控
- **监控 STARTTLS 命令**：记录加密尝试
- **跟踪 SSL 建立事件**：验证加密成功
- **计算加密成功率**：`starttls_success / starttls_attempts * 100%`

### 异常活动检测
- **连接时长异常**：超过预期的连接持续时间
- **数据传输异常**：异常大小的邮件传输
- **认证失败监控**：POP3 登录失败次数

## 测试规则

### 测试环境配置
基于现有 GreenMail 配置：
- **SMTP 测试端口**：`localhost:3025`
- **POP3 测试端口**：`localhost:3110`
- **测试用户**：`demo:demo@localhost.local`

### 测试脚本规范
- 使用现有测试脚本：`scripts/test-smtp.sh`, `scripts/test-pop3.sh`
- 测试结果验证：检查 `output/` 目录下的日志文件
- 功能测试覆盖：简单邮件、附件邮件、HTML 邮件、批量邮件

## 文件组织规则

### 核心文件结构
```
zeek-scripts/
└── mail-activity-json.zeek    # 主监控脚本（所有功能集中）

scripts/
├── run-live.sh               # 实时监控启动
├── run-offline.sh            # 离线分析
├── test-smtp.sh              # SMTP 测试
├── test-pop3.sh              # POP3 测试
└── test-mail-protocols.sh    # 综合测试

docker/greenmail/
└── docker-compose.yml        # 测试邮件服务器

output/
└── live-<timestamp>/         # 监控日志输出
    └── mail_activity.log     # 主要日志文件
```

### 禁止的操作
- ❌ 创建功能重复的新 Zeek 脚本
- ❌ 分散功能到多个小文件
- ❌ 修改核心文件结构
- ❌ 创建不必要的配置文件

### 推荐的操作
- ✅ 在现有脚本中添加新功能
- ✅ 扩展现有数据结构
- ✅ 优化现有事件处理逻辑
- ✅ 增强现有统计功能

## 版本控制规则

### Git 忽略规则
基于现有 `.gitignore` 配置：
- 忽略所有日志文件：`*.log`
- 忽略输出目录内容：`output/` 下的实际日志
- 保留目录结构：保留 `.gitignore` 占位文件

### 提交规范
- 功能增强应作为单个提交
- 删除重复文件应单独提交
- 配置修改应包含测试验证

## 字符编码规范

### 输出字符规范
为避免终端乱码问题，所有脚本输出必须遵循以下规范：

#### 禁止使用的字符
- **Unicode 表情符号**：📧 🔐 📊 ✅ ❌ 等
- **Unicode 边框字符**：╔ ╗ ╚ ╝ ║ ╠ ╣ 等
- **其他非ASCII字符**：任何超出ASCII范围的字符

#### 推荐使用的字符
```zeek
# 状态标识符
[OK]     - 成功状态
[ERROR]  - 错误状态
[WARN]   - 警告状态
[INFO]   - 信息状态

# 协议标识符
[SMTP]   - SMTP 相关消息
[POP3]   - POP3 相关消息
[TLS]    - TLS/加密相关消息
[STATS]  - 统计信息
[MAIL]   - 通用邮件消息

# 边框字符（使用ASCII字符）
+========================================+
||                                      ||
+========================================+
```

#### 日志消息格式标准
```zeek
# 连接消息
print fmt("[SMTP] New SMTP Connection: %s:%d -> %s:%d (HELO: %s)", ...);

# 状态消息
print fmt("[OK] SMTP %s Success: %d %s", cmd, code, msg);
print fmt("[ERROR] SMTP %s Error: %d %s", cmd, code, msg);

# 统计报告
print "+==============================================================+";
print fmt("|| [STATS] Mail Traffic Statistics [%s] ||", timestamp);
print "+==============================================================+";
```

### 编码兼容性
- **终端兼容性**：确保在各种终端环境下正常显示
- **日志文件兼容性**：避免日志文件中出现乱码
- **跨平台兼容性**：在不同操作系统下保持一致显示

## 性能优化规则

### 监控性能
- 统计报告间隔：默认 30 秒，可通过 `report_interval` 调整
- 日志轮转：依赖 Zeek 内置机制
- 内存使用：避免存储大量历史数据

### 网络捕获
- 使用精确的 BPF 过滤器：`port 25 or port 465 or port 587 or port 110 or port 995 or port 3025 or port 3110`
- 避免捕获不相关流量
- 优先监控关键端口

---

**最后更新**：2025-09-18  
**适用版本**：Zeek 8.0.1+  
**维护原则**：基于现有配置修改，避免代码混乱