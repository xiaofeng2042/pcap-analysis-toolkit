# 网络桥接脚本使用说明

## 概述

本项目提供了两个脚本来管理Linux系统的网络桥接配置：

- `setup-bridge.sh` - 创建网络桥接
- `restore-network.sh` - 恢复原始网络配置

## 功能特性

### setup-bridge.sh 功能
- ✅ 自动读取eth0的IP地址和路由配置
- ✅ 创建br0桥接接口
- ✅ 将eth0和tap_tap接口加入桥接
- ✅ 智能处理tap_tap接口不存在的情况
- ✅ 自动备份当前网络配置
- ✅ 完整的错误处理和恢复机制
- ✅ 支持干运行模式预览操作

### restore-network.sh 功能
- ✅ 安全删除br0桥接接口
- ✅ 将IP配置恢复到eth0
- ✅ 自动重启NetworkManager服务
- ✅ 智能检测和恢复网络配置

## 使用方法

### 1. 设置网络桥接

```bash
# 基本使用（需要root权限）
sudo ./scripts/setup-bridge.sh

# 查看帮助信息
./scripts/orb/setup-bridge.sh --help

# 干运行模式（预览将要执行的操作）
./scripts/orb/setup-bridge.sh --dry-run
```

### 2. 恢复网络配置

```bash
# 恢复到桥接前的配置
sudo ./scripts/orb/restore-network.sh

# 查看帮助信息
./scripts/orb/restore-network.sh --help
```

## 脚本执行流程

### setup-bridge.sh 执行步骤

1. **权限检查** - 确保以root权限运行
2. **接口检查** - 验证eth0存在，检查tap_tap是否存在
3. **配置读取** - 自动读取eth0的IP地址和网关信息
4. **配置备份** - 将当前网络配置备份到/tmp/目录
5. **服务停止** - 临时停止NetworkManager避免冲突
6. **地址清空** - 清空eth0和tap_tap的IP地址
7. **桥接创建** - 创建br0桥接接口
8. **接口加入** - 将eth0和tap_tap加入桥接
9. **接口启动** - 启动所有相关网络接口
10. **配置迁移** - 将IP地址和路由迁移到br0
11. **结果显示** - 显示最终的网络配置

### restore-network.sh 执行步骤

1. **权限检查** - 确保以root权限运行
2. **配置检测** - 检测当前br0的IP配置
3. **接口移除** - 从桥接中移除eth0和tap_tap
4. **桥接删除** - 安全删除br0桥接接口
5. **配置恢复** - 将IP配置恢复到eth0
6. **路由恢复** - 重新设置默认路由
7. **服务重启** - 重启NetworkManager服务

## 安全特性

### 错误处理
- 使用`set -e`确保遇到错误立即退出
- 提供cleanup函数在出错时尝试恢复
- 所有关键操作都有错误检查

### 备份机制
- 自动备份当前网络配置到`/tmp/network_backup_YYYYMMDD_HHMMSS.txt`
- 包含IP地址和路由表信息
- 便于手动恢复（如果需要）

### 智能检测
- 自动检测网络接口是否存在
- 智能处理tap_tap接口缺失的情况
- 检测并处理已存在的br0接口

## 使用场景

### 适用场景
- 需要将物理网卡和虚拟网卡桥接
- 虚拟机网络配置
- 容器网络设置
- 网络测试环境搭建

### 典型用例
```bash
# 场景1：基本桥接设置
sudo ./scripts/orb/setup-bridge.sh

# 场景2：预览操作（不实际执行）
./scripts/orb/setup-bridge.sh --dry-run

# 场景3：出现问题时恢复
sudo ./scripts/orb/restore-network.sh
```

## 注意事项

### 系统要求
- Linux系统（支持ip命令）
- root权限
- 存在eth0网络接口

### 重要提醒
- ⚠️ 执行前请确保有其他方式访问系统（如控制台）
- ⚠️ 建议先在测试环境中验证
- ⚠️ 脚本会临时中断网络连接
- ⚠️ 如果tap_tap不存在，脚本会自动跳过相关操作

### 故障排除

#### 常见问题

1. **权限不足**
   ```bash
   [ERROR] 此脚本需要root权限运行
   请使用: sudo ./scripts/setup-bridge.sh
   ```

2. **eth0不存在**
   ```bash
   [ERROR] 网络接口 eth0 不存在
   ```
   解决：检查网络接口名称，可能是ens33、enp0s3等

3. **无法获取IP地址**
   ```bash
   [ERROR] 无法获取 eth0 的IP地址
   ```
   解决：确保eth0已配置IP地址

#### 手动恢复
如果脚本出现问题，可以手动执行以下命令恢复：

```bash
# 删除桥接
sudo ip link set br0 down
sudo ip link delete br0

# 重启网络服务
sudo systemctl restart NetworkManager

# 或者重启网络接口
sudo ifdown eth0 && sudo ifup eth0
```

## 日志和调试

### 日志位置
- 网络配置备份：`/tmp/network_backup_*.txt`
- 系统日志：`/var/log/syslog` 或 `journalctl -u NetworkManager`

### 调试模式
```bash
# 启用bash调试模式
bash -x ./scripts/orb/setup-bridge.sh --dry-run
```

## 版本信息

- 脚本版本：1.0
- 兼容系统：Ubuntu 18.04+, CentOS 7+, Debian 9+
- 依赖工具：ip, bridge, systemctl

## 许可证

本脚本遵循MIT许可证，可自由使用和修改。