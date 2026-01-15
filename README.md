# IOC Network Connection Monitor

IOC 网络连接监控工具 - 基于 IOC（IP/域名）的网络连接实时监控，用于检测系统中与指定 IOC 的网络连接，并输出完整进程链信息。

## 功能特性

- 支持单个 IOC 或批量 IOC 文件输入
- 自动解析域名为 IP 地址
- 监控 TCP/UDP 全部连接状态（包括 SYN_SENT、ESTABLISHED 等）
- 命中时输出完整进程链（进程名、路径、PID、父进程链）
- 结果保存到 `res.txt` 文件
- 纯命令行运行，稳定可靠
- 无第三方依赖

## 使用方法

### 运行要求

- Windows 10/11
- **需要管理员权限运行**

### 启动方式

1. 右键 `ioc-monitor.exe` → 以管理员身份运行
2. 或在管理员命令提示符中运行

### 单个 IOC 监控

```
====================================
  IOC 网络连接监控工具
  IOC Network Connection Monitor
====================================
  需要管理员权限运行
====================================

选择输入方式:
  1. 手动输入单个 IOC
  2. 从文件批量读取 IOC
请选择 (1/2, 默认 1): 1
输入 IOC (IP 或域名): evil.com
输入监控时长 (秒, 默认 60): 600
```

### 批量 IOC 监控

```
请选择 (1/2, 默认 1): 2
输入 IOC 文件路径: C:\ioc.txt
从文件读取到 15 个 IOC

正在解析 IOC...
  [IP] 1.2.3.4
  [域名] evil.com -> [185.203.39.50]
共 15 个 IOC, 解析到 12 个 IP
```

### IOC 文件格式

每行一个 IOC，支持注释：

```
# 恶意域名列表
evil.com
malware.cn
c2server.net

# 恶意 IP
1.2.3.4
5.6.7.8

# 也支持以下格式（自动提取）
http://evil.com/path
https://1.2.3.4:8080/page
evil.com:443
```

支持的格式：
- 纯 IP：`1.2.3.4`
- 纯域名：`evil.com`
- 带端口：`1.2.3.4:8080`、`evil.com:443`
- URL：`http://evil.com/path`、`https://1.2.3.4:8080/`
- IPv6：`2001:db8::1`

## 输出示例

### 控制台输出

```
[16:30:45] 剩余 580 秒 | IOC: 15 | IP: 12 | 命中: 0

[命中] 16:30:47 IOC:evil.com TCP/SYN_SENT 185.203.39.50:443 -> PID:3936 chrome.exe
[16:30:48] 剩余 578 秒 | IOC: 15 | IP: 12 | 命中: 1
```

### res.txt 文件内容

```
================================================================================
时间戳: 2024-01-15 16:30:47
IOC: evil.com
协议: TCP
状态: SYN_SENT
远程地址: 185.203.39.50:443
本地地址: 192.168.1.100:52341
--------------------------------------------------------------------------------
[命中进程]
  PID: 3936
  进程名: chrome.exe
  路径: C:\Program Files\Google\Chrome\Application\chrome.exe
[父进程 1]
  PID: 3900
  进程名: chrome.exe
  路径: C:\Program Files\Google\Chrome\Application\chrome.exe
[父进程 2]
  PID: 1234
  进程名: explorer.exe
  路径: C:\Windows\explorer.exe
================================================================================
```

## 编译方法

### 环境要求

- Go 1.21+

### Windows 本地编译

```cmd
go build -ldflags="-s -w" -o ioc-monitor.exe main.go
```

### macOS/Linux 交叉编译

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o ioc-monitor.exe main.go
```

## 技术说明

- 使用 Windows 原生 API（GetExtendedTcpTable/GetExtendedUdpTable）获取网络连接
- 使用 NtQueryInformationProcess 获取父进程信息
- 无第三方依赖，纯 Go 标准库 + Windows syscall
- 每秒轮询一次网络连接表
- 每 30 秒刷新一次域名解析

## 注意事项

1. 必须以管理员权限运行，否则无法获取完整的网络连接和进程信息
2. 按 `Ctrl+C` 可随时停止监控
3. 结果追加写入 `res.txt`，不会覆盖之前的记录
4. 同一连接（相同远程IP:端口+PID+状态）只记录一次

## License

MIT License
