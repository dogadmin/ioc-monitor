package monitor

import (
	"fmt"
	"strings"
	"time"

	"iocmonitor/ioc"
)

// Matcher IOC 匹配引擎
// 将系统快照与 IOC 集合进行多维匹配
type Matcher struct {
	iocSet      *ioc.IOCSet
	resolver    *ioc.Resolver
	sessionID   string
	checkCmd    bool
	reportedSet map[string]struct{} // 连接级去重: IOC+四元组 → 已报告
}

func NewMatcher(iocSet *ioc.IOCSet, resolver *ioc.Resolver, sessionID string, checkCmd bool) *Matcher {
	return &Matcher{
		iocSet:      iocSet,
		resolver:    resolver,
		sessionID:   sessionID,
		checkCmd:    checkCmd,
		reportedSet: make(map[string]struct{}),
	}
}

// connHitKey 生成连接级去重 key: 同一条 TCP 连接(四元组) + 同一个 IOC 只报一次
func connHitKey(iocValue string, conn ConnectionInfo) string {
	return fmt.Sprintf("%s|%s|%d|%s|%d", iocValue, conn.LocalAddr, conn.LocalPort, conn.RemoteAddr, conn.RemotePort)
}

// alreadyReported 检查并标记是否已报告过
func (m *Matcher) alreadyReported(key string) bool {
	if _, ok := m.reportedSet[key]; ok {
		return true
	}
	m.reportedSet[key] = struct{}{}
	return false
}

// Match 对系统快照执行全量匹配，返回所有命中记录
func (m *Matcher) Match(snap *SystemSnapshot) []HitRecord {
	var hits []HitRecord
	now := time.Now()

	// === 1. 网络连接匹配 ===
	for _, conn := range snap.Connections {
		// 1a. IP IOC 直接匹配远程地址（强命中）
		if m.iocSet.HasIP(conn.RemoteAddr) {
			key := connHitKey(conn.RemoteAddr, conn)
			if !m.alreadyReported(key) {
				iocType := ioc.IOCTypeIPv4
				if strings.Contains(conn.RemoteAddr, ":") {
					iocType = ioc.IOCTypeIPv6
				}
				hits = append(hits, m.hitFromConn(now, conn, conn.RemoteAddr, iocType, HitStrong,
					conn.Protocol+"连接", "IP 直接匹配远程连接地址"))
			}
		}

		// 1b. 域名解析后的 IP 匹配（强命中）
		if domains := m.resolver.LookupDomainByIP(conn.RemoteAddr); len(domains) > 0 {
			for _, domain := range domains {
				if m.iocSet.HasDomain(domain) {
					key := connHitKey(domain, conn)
					if !m.alreadyReported(key) {
						hits = append(hits, m.hitFromConn(now, conn, domain, ioc.IOCTypeDomain, HitStrong,
							conn.Protocol+"连接(域名解析)",
							"域名 "+domain+" 解析到 "+conn.RemoteAddr+" 匹配远程连接"))
					}
				}
			}
		}

		// 1c. 进程命令行包含 IOC（弱命中）
		if m.checkCmd && conn.CmdLine != "" {
			cmdLower := strings.ToLower(conn.CmdLine)
			for _, entry := range m.iocSet.Entries {
				if strings.Contains(cmdLower, strings.ToLower(entry.Value)) {
					key := connHitKey(entry.Value, conn)
					if !m.alreadyReported(key) {
						hits = append(hits, m.hitFromConn(now, conn, entry.Value, entry.Type, HitWeak,
							"命令行匹配", "进程命令行包含 IOC 值: "+entry.Value))
					}
				}
			}
		}
	}

	// === 2. DNS 缓存: 不单独命中，仅用于补充 IP→域名 映射 ===
	// 已在 Engine 层通过 resolver.MergeDNSCache() 完成

	// === 3. hosts 文件匹配 ===
	for _, entry := range snap.HostsEntries {
		for _, domain := range entry.Domains {
			if m.iocSet.HasDomain(domain) {
				key := fmt.Sprintf("hosts|%s|%s", domain, entry.IP)
				if !m.alreadyReported(key) {
					hits = append(hits, HitRecord{
						Time:      now,
						SessionID: m.sessionID,
						IOCType:   ioc.IOCTypeDomain,
						IOCValue:  domain,
						Source:    "hosts文件",
						Strength:  HitWeak,
						Note:      "hosts文件中 " + domain + " 指向 " + entry.IP,
					})
				}
			}
		}
		if m.iocSet.HasIP(entry.IP) {
			key := fmt.Sprintf("hosts|%s", entry.IP)
			if !m.alreadyReported(key) {
				hits = append(hits, HitRecord{
					Time:      now,
					SessionID: m.sessionID,
					IOCType:   ioc.IOCTypeIPv4,
					IOCValue:  entry.IP,
					Source:    "hosts文件",
					Strength:  HitWeak,
					Note:      "hosts文件中此IP关联域名: " + strings.Join(entry.Domains, ", "),
				})
			}
		}
	}

	return hits
}

// hitFromConn 从连接信息构建命中记录
func (m *Matcher) hitFromConn(t time.Time, conn ConnectionInfo, iocValue string,
	iocType ioc.IOCType, strength HitStrength, source, note string) HitRecord {
	return HitRecord{
		Time:        t,
		SessionID:   m.sessionID,
		IOCType:     iocType,
		IOCValue:    iocValue,
		Source:      source,
		Strength:    strength,
		ProcessName: conn.ProcessName,
		PID:         conn.PID,
		ParentPID:   conn.ParentPID,
		CmdLine:     conn.CmdLine,
		Username:    conn.Username,
		LocalAddr:   conn.LocalAddr,
		LocalPort:   conn.LocalPort,
		RemoteAddr:  conn.RemoteAddr,
		RemotePort:  conn.RemotePort,
		Protocol:    conn.Protocol,
		ConnState:   conn.State,
		Note:        note,
	}
}
