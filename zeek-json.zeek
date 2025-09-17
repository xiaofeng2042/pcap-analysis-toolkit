# Zeek配置文件：默认输出JSON格式日志
# 使用方法：zeek -C -r file.pcap zeek-json.zeek

# 设置所有日志输出为JSON格式
redef LogAscii::use_json = T;

# 可选：设置JSON输出的时间戳格式
# redef LogAscii::json_timestamps = JSON::TS_ISO8601;

# 可选：美化JSON输出（增加缩进，但会增加文件大小）
# redef LogAscii::json_include_meta = F;

# 可选：禁用某些不需要的日志
# redef Log::default_logdir = ".";

print "Zeek配置已加载：所有日志将以JSON格式输出";