package ioc

import (
	"net"
	"strings"
)

// IOCSet 已解析、去重的 IOC 集合，提供 O(1) 查找
type IOCSet struct {
	Entries   []IOCEntry
	ipSet     map[string]struct{} // 标准化IP -> 存在标记
	domainSet map[string]struct{} // 小写域名 -> 存在标记
	allValues map[string]struct{} // 全部值（小写）用于去重
}

// Parse 解析用户输入文本为 IOCSet
// 自动: trim、去空行、去重、分类(IPv4/IPv6/域名)、标准化
func Parse(input string) *IOCSet {
	set := &IOCSet{
		ipSet:     make(map[string]struct{}),
		domainSet: make(map[string]struct{}),
		allValues: make(map[string]struct{}),
	}

	lines := strings.Split(input, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 去重 (大小写不敏感)
		normalized := strings.ToLower(line)
		if _, exists := set.allValues[normalized]; exists {
			continue
		}

		entry := IOCEntry{Original: line}

		if ip := net.ParseIP(line); ip != nil {
			// IP 地址
			if ip.To4() != nil {
				entry.Type = IOCTypeIPv4
			} else {
				entry.Type = IOCTypeIPv6
			}
			entry.Value = ip.String()
			set.ipSet[entry.Value] = struct{}{}
		} else {
			// 当作域名
			entry.Type = IOCTypeDomain
			entry.Value = strings.ToLower(strings.TrimSuffix(line, "."))
			set.domainSet[entry.Value] = struct{}{}
		}

		set.allValues[normalized] = struct{}{}
		set.Entries = append(set.Entries, entry)
	}

	return set
}

// Count 返回 IOC 总数
func (s *IOCSet) Count() int {
	return len(s.Entries)
}

// HasIP 检查某个 IP 是否在 IOC 集合中
func (s *IOCSet) HasIP(ip string) bool {
	// 标准化后查找
	parsed := net.ParseIP(ip)
	if parsed == nil {
		_, ok := s.ipSet[ip]
		return ok
	}
	_, ok := s.ipSet[parsed.String()]
	return ok
}

// HasDomain 检查某个域名是否在 IOC 集合中
func (s *IOCSet) HasDomain(domain string) bool {
	_, ok := s.domainSet[strings.ToLower(domain)]
	return ok
}

// GetDomains 返回所有域名 IOC
func (s *IOCSet) GetDomains() []string {
	domains := make([]string, 0, len(s.domainSet))
	for d := range s.domainSet {
		domains = append(domains, d)
	}
	return domains
}

// GetIPs 返回所有 IP IOC
func (s *IOCSet) GetIPs() []string {
	ips := make([]string, 0, len(s.ipSet))
	for ip := range s.ipSet {
		ips = append(ips, ip)
	}
	return ips
}

// Text 导出为文本（一行一个）
func (s *IOCSet) Text() string {
	var sb strings.Builder
	for i, e := range s.Entries {
		if i > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(e.Value)
	}
	return sb.String()
}
