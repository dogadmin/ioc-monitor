package monitor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	psnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// Collector 系统数据采集器，负责收集网络连接、DNS缓存、hosts文件
type Collector struct {
	checkDNS     bool
	checkHosts   bool
	lastDNS      time.Time
	dnsInterval  time.Duration
	cachedDNS    []DNSCacheEntry
	processCache map[int32]*procInfo
}

type procInfo struct {
	Name     string
	CmdLine  string
	PPID     int32
	Username string
	Err      string
}

func NewCollector(checkDNS, checkHosts bool) *Collector {
	return &Collector{
		checkDNS:     checkDNS,
		checkHosts:   checkHosts,
		dnsInterval:  10 * time.Second,
		processCache: make(map[int32]*procInfo),
	}
}

// Collect 执行一次完整的系统快照采集
func (c *Collector) Collect(ctx context.Context) *SystemSnapshot {
	snap := &SystemSnapshot{
		CollectTime: time.Now(),
	}

	// 网络连接（每次必采）
	c.collectConnections(ctx, snap)

	// DNS 缓存（降频，每 10 秒一次）
	if c.checkDNS && time.Since(c.lastDNS) >= c.dnsInterval {
		c.collectDNSCache(ctx, snap)
		c.lastDNS = time.Now()
	} else if c.checkDNS {
		snap.DNSCache = c.cachedDNS
	}

	// hosts 文件
	if c.checkHosts {
		c.collectHostsFile(snap)
	}

	return snap
}

// collectConnections 枚举所有 TCP/UDP 连接及关联进程信息
func (c *Collector) collectConnections(ctx context.Context, snap *SystemSnapshot) {
	c.processCache = make(map[int32]*procInfo) // 每轮清空重建

	conns, err := psnet.ConnectionsWithContext(ctx, "all")
	if err != nil {
		snap.Errors = append(snap.Errors, fmt.Sprintf("获取网络连接失败: %v", err))
		return
	}

	for _, conn := range conns {
		// 过滤无远程地址的连接（监听、未连接等）
		if conn.Raddr.IP == "" || conn.Raddr.IP == "0.0.0.0" || conn.Raddr.IP == "::" || conn.Raddr.IP == "*" {
			continue
		}

		// 过滤非活跃 TCP 状态：TIME_WAIT 等残留连接进程已退出(PID=0)，不应命中
		if conn.Status == "TIME_WAIT" || conn.Status == "CLOSING" ||
			conn.Status == "LAST_ACK" || conn.Status == "DELETE_TCB" {
			continue
		}

		ci := ConnectionInfo{
			LocalAddr:  conn.Laddr.IP,
			LocalPort:  conn.Laddr.Port,
			RemoteAddr: conn.Raddr.IP,
			RemotePort: conn.Raddr.Port,
			State:      conn.Status,
			PID:        conn.Pid,
		}

		// 协议判断
		switch conn.Type {
		case 1: // SOCK_STREAM -> TCP
			ci.Protocol = "TCP"
		case 2: // SOCK_DGRAM -> UDP
			ci.Protocol = "UDP"
		default:
			ci.Protocol = fmt.Sprintf("TYPE_%d", conn.Type)
		}

		// 进程信息（带 PID 缓存，同一轮扫描中同 PID 只查一次）
		if conn.Pid > 0 {
			pi := c.getProcessInfo(conn.Pid)
			ci.ProcessName = pi.Name
			ci.CmdLine = pi.CmdLine
			ci.ParentPID = pi.PPID
			ci.Username = pi.Username
			ci.ProcessErr = pi.Err
		}

		snap.Connections = append(snap.Connections, ci)
	}
}

// getProcessInfo 获取进程详情，同一轮扫描内带缓存
func (c *Collector) getProcessInfo(pid int32) *procInfo {
	if cached, ok := c.processCache[pid]; ok {
		return cached
	}

	pi := &procInfo{}

	p, err := process.NewProcess(pid)
	if err != nil {
		pi.Err = fmt.Sprintf("无法打开进程: %v", err)
		c.processCache[pid] = pi
		return pi
	}

	var errs []string

	if name, err := p.Name(); err != nil {
		errs = append(errs, fmt.Sprintf("进程名: %v", err))
	} else {
		pi.Name = name
	}

	if cmdline, err := p.Cmdline(); err != nil {
		errs = append(errs, fmt.Sprintf("命令行: %v", err))
	} else {
		pi.CmdLine = cmdline
	}

	if ppid, err := p.Ppid(); err != nil {
		errs = append(errs, fmt.Sprintf("父进程: %v", err))
	} else {
		pi.PPID = ppid
	}

	if username, err := p.Username(); err != nil {
		errs = append(errs, fmt.Sprintf("用户名: %v", err))
	} else {
		pi.Username = username
	}

	if len(errs) > 0 {
		pi.Err = strings.Join(errs, "; ")
	}

	c.processCache[pid] = pi
	return pi
}

// collectDNSCache 通过 PowerShell 读取 Windows DNS 客户端缓存
func (c *Collector) collectDNSCache(ctx context.Context, snap *SystemSnapshot) {
	ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx2, "powershell", "-NoProfile", "-Command",
		"Get-DnsClientCache | Select-Object Entry,Data,Type | ConvertTo-Json -Compress")
	output, err := cmd.Output()
	if err != nil {
		snap.Errors = append(snap.Errors, fmt.Sprintf("DNS缓存获取失败: %v", err))
		return
	}

	if len(output) == 0 {
		return
	}

	type dnsRaw struct {
		Entry string `json:"Entry"`
		Data  string `json:"Data"`
		Type  int    `json:"Type"`
	}

	var entries []dnsRaw
	if err := json.Unmarshal(output, &entries); err != nil {
		// PowerShell 单条记录时返回对象而非数组
		var single dnsRaw
		if err2 := json.Unmarshal(output, &single); err2 != nil {
			snap.Errors = append(snap.Errors, fmt.Sprintf("DNS缓存解析失败: %v", err))
			return
		}
		entries = []dnsRaw{single}
	}

	// 按域名聚合 IP
	domainIPs := make(map[string][]string)
	for _, e := range entries {
		if e.Data != "" && e.Entry != "" {
			key := strings.ToLower(e.Entry)
			domainIPs[key] = appendUniqueStr(domainIPs[key], e.Data)
		}
	}

	snap.DNSCache = nil
	for domain, ips := range domainIPs {
		snap.DNSCache = append(snap.DNSCache, DNSCacheEntry{Domain: domain, IPs: ips})
	}
	c.cachedDNS = snap.DNSCache
}

// collectHostsFile 读取系统 hosts 文件
func (c *Collector) collectHostsFile(snap *SystemSnapshot) {
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	hostsPath := filepath.Join(sysRoot, "System32", "drivers", "etc", "hosts")

	f, err := os.Open(hostsPath)
	if err != nil {
		snap.Errors = append(snap.Errors, fmt.Sprintf("hosts文件读取失败: %v", err))
		return
	}
	defer f.Close()

	ipDomains := make(map[string][]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || net.ParseIP(fields[0]) == nil {
			continue
		}
		ip := fields[0]
		for _, domain := range fields[1:] {
			if strings.HasPrefix(domain, "#") {
				break
			}
			ipDomains[ip] = appendUniqueStr(ipDomains[ip], strings.ToLower(domain))
		}
	}

	for ip, domains := range ipDomains {
		snap.HostsEntries = append(snap.HostsEntries, HostsEntry{IP: ip, Domains: domains})
	}
}

func appendUniqueStr(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}
