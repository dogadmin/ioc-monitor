package monitor

import (
	"time"

	"iocmonitor/ioc"
)

// HitStrength 命中强度分级
type HitStrength int

const (
	HitStrong HitStrength = iota // 强命中: IP直接匹配连接 / 域名解析IP匹配连接
	HitMedium                    // 中命中: DNS缓存中发现域名
	HitWeak                      // 弱命中: 命令行包含 / hosts文件存在
)

func (s HitStrength) String() string {
	switch s {
	case HitStrong:
		return "强命中"
	case HitMedium:
		return "中命中"
	case HitWeak:
		return "弱命中"
	default:
		return "未知"
	}
}

// HitRecord 一条命中记录，包含完整上下文
type HitRecord struct {
	Time        time.Time
	SessionID   string
	IOCType     ioc.IOCType
	IOCValue    string
	Source      string      // TCP连接、UDP连接、DNS缓存、命令行、hosts文件
	Strength    HitStrength
	ProcessName string
	PID         int32
	ParentPID   int32
	CmdLine     string
	Username    string
	LocalAddr   string
	LocalPort   uint32
	RemoteAddr  string
	RemotePort  uint32
	Protocol    string
	ConnState   string
	Note        string // 关联说明
}

// ConnectionInfo 网络连接信息（单条）
type ConnectionInfo struct {
	Protocol    string // TCP / UDP
	LocalAddr   string
	LocalPort   uint32
	RemoteAddr  string
	RemotePort  uint32
	State       string
	PID         int32
	ProcessName string
	CmdLine     string
	ParentPID   int32
	Username    string
	ProcessErr  string // 进程信息获取失败原因
}

// DNSCacheEntry DNS 缓存条目
type DNSCacheEntry struct {
	Domain string
	IPs    []string
}

// HostsEntry hosts 文件条目
type HostsEntry struct {
	IP      string
	Domains []string
}

// SystemSnapshot 单次采集的系统快照
type SystemSnapshot struct {
	Connections  []ConnectionInfo
	DNSCache     []DNSCacheEntry
	HostsEntries []HostsEntry
	CollectTime  time.Time
	Errors       []string
}

// EngineCallbacks 引擎回调接口，用于通知 GUI
type EngineCallbacks struct {
	OnHit    func(HitRecord) bool          // 返回 false 表示用户要求停止
	OnLog    func(string)                   // 实时日志
	OnTick   func(elapsed, remaining int, scanCount int64) // 每秒刷新
	OnFinish func()                         // 监控结束
}
