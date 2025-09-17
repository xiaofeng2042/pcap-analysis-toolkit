# MailHog 本地快速验证指南（macOS）

MailHog 是一个轻量级 SMTP 捕获服务，适合在本地测试邮件发送逻辑，所有邮件会被捕获并通过 Web UI 展示，不会真正发往互联网。

## 1. 前置条件

- macOS 设备
- 安装 [Docker Desktop](https://www.docker.com/products/docker-desktop/)
  - 安装后首次运行需完成 Docker Desktop 初始化

## 2. 启动 MailHog

项目已提供 `docker/mailhog/docker-compose.yml` 与脚本，按以下步骤即可：

```bash
# 第一次需要授予执行权限
chmod +x scripts/start-mailhog.sh scripts/stop-mailhog.sh

# 启动 MailHog（后台运行）
./scripts/start-mailhog.sh
```

启动成功输出将提示 SMTP 监听端口 `1025`、Web UI 端口 `8025`。

在浏览器访问 [http://localhost:8025](http://localhost:8025) 可以查看捕获到的邮件。

## 3. 发送测试邮件

示例使用 `swaks`（Swiss Army Knife for SMTP）：

```bash
# 如果未安装 swaks，可通过 Homebrew 安装
brew install swaks

# 发送一封测试邮件到 MailHog
swaks --to test@example.com --from demo@local.test --server localhost:1025 --data 'Subject: MailHog test\n\nHello MailHog!'
```

其他语言或服务可以将 SMTP 主机改为 `localhost`，端口改为 `1025`，即可把邮件送入 MailHog。

## 4. 停止服务

```bash
./scripts/stop-mailhog.sh
```

> 如需清理容器残留，可在 Docker Desktop 中手动移除 `mailhog` 容器。

## 5. 进阶：与本项目监控脚本联动

- 让需要被监控的服务把邮件投递到 `localhost:1025`
- 脚本已默认将 MailHog 的 `1025/tcp` 注册为 SMTP 端口；若有额外自定义端口，可在 `zeek-scripts/site-smtp-ports.zeek` 里追加 `redef`
- 配置本项目的抓包/Zeek 监控针对 `127.0.0.1` 上的 SMTP 流量
- macOS 回环接口上校验和常为 0，本仓库脚本已通过 `redef ignore_checksums = T;` 避免丢包
- 使用 MailHog 的 Web UI 验证邮件是否被捕获，与 Zeek 日志对照分析

这样即可在 macOS 上构建一个安全、可控的邮件发送实验环境，无需真实邮件服务器。EOF
