#!/usr/bin/env python3
import json
import sys

def parse_zeek_smtp_log(log_file):
    """解析Zeek SMTP日志文件并转换为JSON格式"""
    results = []
    
    with open(log_file, 'r') as f:
        lines = f.readlines()
    
    # 找到字段定义行
    fields_line = None
    types_line = None
    
    for line in lines:
        if line.startswith('#fields'):
            fields_line = line.strip().split('\t')[1:]  # 去掉#fields
        elif line.startswith('#types'):
            types_line = line.strip().split('\t')[1:]   # 去掉#types
        elif not line.startswith('#') and line.strip():
            # 这是数据行
            if fields_line and types_line:
                values = line.strip().split('\t')
                
                # 创建JSON对象
                smtp_record = {}
                
                for i, field in enumerate(fields_line):
                    if i < len(values):
                        value = values[i]
                        field_type = types_line[i] if i < len(types_line) else 'string'
                        
                        # 处理不同的数据类型
                        if value == '-':
                            # Zeek中的未设置字段
                            continue
                        elif value == '(empty)':
                            # Zeek中的空字段
                            smtp_record[field] = ""
                        elif field_type == 'time':
                            smtp_record[field] = float(value)
                        elif field_type == 'count' or field_type == 'port':
                            smtp_record[field] = int(value)
                        elif field_type == 'bool':
                            smtp_record[field] = value == 'T'
                        elif field_type.startswith('set[') or field_type.startswith('vector['):
                            # 处理集合和向量类型
                            if ',' in value:
                                smtp_record[field] = value.split(',')
                            else:
                                smtp_record[field] = [value] if value else []
                        else:
                            smtp_record[field] = value
                
                results.append(smtp_record)
    
    return results

def main():
    if len(sys.argv) != 2:
        print("使用方法: python3 convert_smtp_to_json.py <smtp.log>")
        sys.exit(1)
    
    log_file = sys.argv[1]
    
    try:
        smtp_records = parse_zeek_smtp_log(log_file)
        
        # 输出JSON格式
        for record in smtp_records:
            print(json.dumps(record, indent=2, ensure_ascii=False))
            
    except FileNotFoundError:
        print(f"错误: 找不到文件 {log_file}")
        sys.exit(1)
    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()