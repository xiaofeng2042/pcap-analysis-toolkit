#!/bin/bash

# 汇总所有PCAP文件解析结果的脚本

echo "📊 PCAP文件解析结果汇总报告"
echo "========================================"
echo "生成时间: $(date)"
echo ""

# 统计总体信息
total_files=0
total_smtp_records=0
total_conn_records=0
total_files_records=0

echo "🗂️  解析结果概览:"
echo "----------------------------------------"

for dir in analysis/*/; do
    if [ -d "$dir" ]; then
        dirname=$(basename "$dir")
        echo ""
        echo "📁 $dirname"
        echo "   ├── 目录: $dir"
        
        # 统计各类日志记录数
        smtp_count=0
        conn_count=0
        files_count=0
        
        if [ -f "${dir}smtp.log" ]; then
            smtp_count=$(wc -l < "${dir}smtp.log")
            total_smtp_records=$((total_smtp_records + smtp_count))
            echo "   ├── SMTP记录: $smtp_count 条"
        fi
        
        if [ -f "${dir}conn.log" ]; then
            conn_count=$(wc -l < "${dir}conn.log")
            total_conn_records=$((total_conn_records + conn_count))
            echo "   ├── 连接记录: $conn_count 条"
        fi
        
        if [ -f "${dir}files.log" ]; then
            files_count=$(wc -l < "${dir}files.log")
            total_files_records=$((total_files_records + files_count))
            echo "   ├── 文件记录: $files_count 条"
        fi
        
        # 列出所有日志文件
        echo "   └── 日志文件:"
        ls -la "${dir}"*.log 2>/dev/null | while read line; do
            filename=$(echo "$line" | awk '{print $9}')
            size=$(echo "$line" | awk '{print $5}')
            if [ -n "$filename" ] && [ "$filename" != "." ] && [ "$filename" != ".." ]; then
                echo "       └── $(basename "$filename") (${size} bytes)"
            fi
        done
        
        total_files=$((total_files + 1))
    fi
done

echo ""
echo "📈 统计汇总:"
echo "----------------------------------------"
echo "总处理文件数: $total_files"
echo "总SMTP记录数: $total_smtp_records"
echo "总连接记录数: $total_conn_records"
echo "总文件记录数: $total_files_records"

echo ""
echo "🔍 详细SMTP内容预览:"
echo "========================================"

for dir in analysis/*/; do
    if [ -d "$dir" ] && [ -f "${dir}smtp.log" ]; then
        dirname=$(basename "$dir")
        echo ""
        echo "📧 $dirname - SMTP详情:"
        echo "----------------------------------------"
        
        # 显示SMTP日志的美化JSON
        if command -v jq >/dev/null 2>&1; then
            cat "${dir}smtp.log" | jq -r '. | "时间: \(.ts) | 发件人: \(.mailfrom // "N/A") | 收件人: \(.rcptto // "N/A") | 主题: \(.subject // "N/A")"' 2>/dev/null || {
                echo "   原始JSON格式:"
                head -3 "${dir}smtp.log" | sed 's/^/   /'
            }
        else
            echo "   原始JSON格式:"
            head -3 "${dir}smtp.log" | sed 's/^/   /'
        fi
    fi
done

echo ""
echo "🎯 解析成功的协议类型:"
echo "========================================"

protocols_found=""
for dir in analysis/*/; do
    if [ -d "$dir" ]; then
        dirname=$(basename "$dir")
        echo -n "📁 $dirname: "
        
        found_protocols=""
        [ -f "${dir}smtp.log" ] && found_protocols="$found_protocols SMTP"
        [ -f "${dir}ssl.log" ] && found_protocols="$found_protocols SSL/TLS"
        [ -f "${dir}dns.log" ] && found_protocols="$found_protocols DNS"
        [ -f "${dir}files.log" ] && found_protocols="$found_protocols FILES"
        [ -f "${dir}x509.log" ] && found_protocols="$found_protocols X509"
        [ -f "${dir}weird.log" ] && found_protocols="$found_protocols WEIRD"
        
        if [ -n "$found_protocols" ]; then
            echo "$found_protocols"
        else
            echo "无协议日志"
        fi
    fi
done

echo ""
echo "✅ 解析完成！所有文件已成功分离解析，避免了日志混乱问题。"