# PCAP文件分析工具集

这个项目包含了使用Zeek网络安全监控工具分析PCAP文件的完整解决方案，特别专注于SMTP协议的解析和JSON格式输出。

## 📁 项目结构

```
├── analysis/                    # 各个PCAP文件的独立解析结果
│   ├── sample-imf/             # sample-imf.pcap 解析结果
│   ├── sample-TNEF/            # sample-TNEF.pcap 解析结果  
│   ├── smtp/                   # smtp.pcap 解析结果
│   ├── smtp-ssl/               # smtp-ssl.pcapng 解析结果
│   └── smtp2525-ssl/           # smtp2525-ssl.pcapng 解析结果
├── *.pcap/*.pcapng             # 原始PCAP文件
├── analyze_all_pcaps.sh        # 批量解析脚本
├── summary_analysis.sh         # 解析结果汇总脚本
├── convert_smtp_to_json.py     # SMTP日志转JSON工具
└── zeek-json.zeek              # Zeek JSON输出配置
```

## 🚀 快速开始

### 1. 批量解析所有PCAP文件

```bash
./analyze_all_pcaps.sh
```

### 2. 查看解析结果汇总

```bash
./summary_analysis.sh
```

### 3. 单独解析特定文件

```bash
# 清理之前的日志
rm -f *.log

# 解析单个文件并输出JSON格式
zeek -C -r your_file.pcap zeek-json.zeek

# 查看SMTP日志
cat smtp.log | jq .
```

## 📊 解析结果

项目成功解析了5个PCAP文件：

- **sample-imf.pcap**: 包含完整SMTP邮件传输，带附件
- **sample-TNEF.pcap**: 包含多个附件的SMTP邮件
- **smtp-ssl.pcapng**: SSL加密的SMTP连接
- **smtp.pcap**: 标准SMTP邮件传输
- **smtp2525-ssl.pcapng**: 异常端口的SSL连接

### 统计数据
- 总SMTP记录数: 4条
- 总连接记录数: 45条  
- 总文件记录数: 8条

## 🛠️ 工具说明

### analyze_all_pcaps.sh
批量解析脚本，为每个PCAP文件创建独立的输出目录，避免日志混乱。

### summary_analysis.sh  
生成详细的解析结果汇总报告，包括统计信息和SMTP内容预览。

### convert_smtp_to_json.py
将Zeek的SMTP日志转换为标准JSON格式的Python脚本。

### zeek-json.zeek
Zeek配置文件，设置所有日志默认输出为JSON格式。

## 📋 解析的协议类型

- **SMTP**: 邮件传输协议
- **SSL/TLS**: 加密连接
- **DNS**: 域名解析
- **FILES**: 文件传输记录
- **X509**: 证书信息
- **CONN**: 网络连接记录

## 🔧 依赖要求

- Zeek网络安全监控工具
- jq (JSON处理工具)
- Python 3.x (用于转换脚本)

## 💡 使用技巧

1. **避免日志混乱**: 始终为每个PCAP文件使用独立的输出目录
2. **JSON格式输出**: 使用 `LogAscii::use_json=T` 参数或配置文件
3. **单文件处理**: 一次只处理一个PCAP文件以获得最佳结果
4. **美化输出**: 使用 `jq .` 命令美化JSON输出

## 📝 示例输出

```json
{
  "ts": 1182675363.843094,
  "uid": "CfkGrakgmF4BNVkQl",
  "id.orig_h": "192.168.1.4",
  "mailfrom": "sender@example.com",
  "rcptto": ["recipient@example.com"],
  "subject": "Test message for capture",
  "tls": false
}
```

## 🎯 关键特性

- ✅ 完全避免日志混乱
- ✅ JSON格式输出  
- ✅ 协议完整解析
- ✅ 可重复执行
- ✅ 详细统计报告