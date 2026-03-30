# IOC Monitor - Windows 本地 IOC 监控工具

[![Build & Release](https://github.com/dogadmin/ioc-monitor/actions/workflows/release.yml/badge.svg)](https://github.com/dogadmin/ioc-monitor/actions/workflows/release.yml)

基于 Go 重构的 Windows 本地 GUI 程序，用于实时监控用户输入的 IOC（域名/IP）在本机的命中情况。

> **v2.0 — 代码重构 + GUI 重写**
>
> 整体架构重构为分层设计（IOC 解析 → 系统采集 → 匹配引擎 → 告警管理 → GUI），新增 Walk 原生 Windows GUI，支持命中表格、实时日志、状态面板等可视化组件。

## 下载

前往 [Releases](https://github.com/dogadmin/ioc-monitor/releases) 下载预编译版本：

| 文件 | 架构 |
|------|------|
| `iocmonitor-x64.exe` | Windows x64 (AMD64) |
| `iocmonitor-arm64.exe` | Windows ARM64 |
| `iocmonitor-x86.exe` | Windows x86 (32位) |

## 功能特性

- **IOC 输入**：支持域名、IPv4、IPv6，批量输入（一行一个），自动去重、分类、标准化
- **实时监控**：每秒扫描系统状态，多维度检测：
  - TCP/UDP 网络连接远程地址匹配（**强命中**）
  - 域名 DNS 解析 IP 匹配连接（**强命中**）
  - Windows DNS 客户端缓存关联（补充 IP→域名 映射）
  - 进程命令行包含 IOC（**弱命中**）
  - hosts 文件包含 IOC（**弱命中**）
- **告警系统**：命中弹窗告警 + 连接级去重 + 可选"仅首次弹窗"模式
- **结果记录**：命中记录追加写入 `res.txt`，含完整进程/连接上下文
- **GUI 面板**：
  - 命中记录表格（时间、IOC、来源、强度、进程、远程地址）
  - 实时滚动日志
  - 状态面板（扫描次数、命中次数、剩余时间、会话信息）
  - IOC 导入/导出
  - 配置自动持久化

## 界面预览

启动后主界面分为三个区域：

1. **上半部分**：左侧 IOC 输入框 + 右侧控制面板（时长设置、启停按钮、检测选项、状态信息）
2. **中部**：命中记录表格，最新记录置顶
3. **下部**：实时日志滚动输出

## 使用说明

1. 双击运行 `iocmonitor-x64.exe`（推荐以管理员身份运行，可获取更完整的进程信息）
2. 在左侧文本框输入待监控的 IOC（域名或 IP），一行一个
3. 设置监控时长（默认 60 秒），点击 **开始监控**
4. 命中时弹窗告警，选择「是」继续 /「否」停止
5. 结果自动写入程序目录下的 `res.txt`

## 项目结构

```
iocmonitor/
├── main.go                  # 程序入口
├── config/
│   └── config.go            # JSON 配置持久化
├── ioc/
│   ├── types.go             # IOC 类型定义 (IPv4/IPv6/Domain)
│   ├── parser.go            # IOC 解析、去重、分类、O(1) 查找
│   └── resolver.go          # 域名 DNS 解析 + IP→域名 反查缓存
├── monitor/
│   ├── types.go             # 命中记录、连接信息、快照等类型
│   ├── engine.go            # 监控主循环 (采集→匹配→告警)
│   ├── collector.go         # 系统数据采集 (连接/DNS缓存/hosts)
│   └── matcher.go           # 多维 IOC 匹配 + 连接级去重
├── alert/
│   ├── manager.go           # 告警去重、分发、弹窗控制
│   └── logger.go            # res.txt 命中日志写入
├── gui/
│   ├── window.go            # 主窗口布局与事件绑定
│   ├── model.go             # 命中表格数据模型
│   └── dialogs.go           # 告警弹窗
└── .github/workflows/
    └── release.yml          # CI: 推送 tag 自动构建三平台 Release
```

## 手动构建

```bash
# 环境: Go 1.21+, Windows

# 安装 rsrc (嵌入 Windows manifest)
go install github.com/akavel/rsrc@latest

# 生成资源文件
rsrc -manifest iocmonitor.manifest -o rsrc_windows_amd64.syso

# 构建 (-H windowsgui 隐藏控制台窗口, -s -w 缩减体积)
go build -ldflags="-H windowsgui -s -w" -o iocmonitor.exe
```

## 自动发布

推送 `v*` 格式的 tag 即可触发 GitHub Actions 自动构建并发布 Release：

```bash
git tag v2.0.0
git push origin v2.0.0
```

CI 会自动编译 Windows x64/ARM64/x86 三个版本并上传到 Release 页面。

## 技术选型

| 组件 | 选择 | 理由 |
|------|------|------|
| GUI | [Walk](https://github.com/lxn/walk) | Windows 原生控件、体积小、原生 MessageBox |
| 系统监控 | [gopsutil](https://github.com/shirou/gopsutil) | 成熟的跨平台系统信息库，纯 Go |
| DNS 缓存 | PowerShell | 官方 `Get-DnsClientCache` cmdlet |
| CI/CD | GitHub Actions | 推送 tag 自动构建三平台 Release |

## 已知限制

1. Windows 上网络连接只能获取远程 IP，无法直接关联原始域名
2. 域名匹配依赖 DNS 预解析和缓存对比，存在不确定性
3. 部分进程信息需管理员权限才能完整获取
4. DNS 缓存采集依赖 PowerShell，频率为每 10 秒一次
5. Walk GUI 框架仅支持 Windows 平台

## License

MIT
