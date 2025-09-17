#!/bin/bash

# 批量解析所有PCAP文件的脚本
# 每个文件解析到独立目录，避免日志混乱

echo "🚀 开始批量解析PCAP文件..."
echo "=================================="

# 定义文件列表
files=(
    "sample-imf.pcap"
    "sample-TNEF.pcap" 
    "smtp-ssl.pcapng"
    "smtp.pcap"
    "smtp2525-ssl.pcapng"
)

# 逐个处理每个文件
for file in "${files[@]}"; do
    if [ -f "$file" ]; then
        # 获取文件名（不含扩展名）
        basename=$(basename "$file" | sed 's/\.[^.]*$//')
        output_dir="analysis/$basename"
        
        echo ""
        echo "📁 处理文件: $file"
        echo "📂 输出目录: $output_dir"
        echo "-----------------------------------"
        
        # 切换到输出目录
        cd "$output_dir"
        
        # 运行Zeek解析，输出JSON格式
        echo "🔍 正在解析..."
        zeek -C -r "../../$file" ../../zeek-json.zeek
        
        # 检查生成的日志文件
        if [ -f "smtp.log" ]; then
            echo "✅ SMTP日志已生成"
            echo "📊 SMTP记录数: $(wc -l < smtp.log)"
        fi
        
        if [ -f "conn.log" ]; then
            echo "✅ 连接日志已生成"  
            echo "📊 连接记录数: $(wc -l < conn.log)"
        fi
        
        echo "📋 生成的日志文件:"
        ls -la *.log 2>/dev/null | awk '{print "   " $9 " (" $5 " bytes)"}'
        
        # 返回主目录
        cd - > /dev/null
        
    else
        echo "❌ 文件不存在: $file"
    fi
done

echo ""
echo "🎉 所有文件解析完成！"
echo "=================================="
echo "📁 查看结果目录结构:"
ls -la analysis/*/