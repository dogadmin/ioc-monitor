package ioc

import (
	"context"
	"net"
	"sync"
	"time"
)

// Resolver 域名 DNS 解析器，带本地缓存
// 用于将域名 IOC 解析为 IP，建立 IP→域名 反查映射
type Resolver struct {
	mu         sync.RWMutex
	cache      map[string]*resolveResult // domain -> 解析结果
	ipToDomain map[string][]string       // 已解析的 IP -> 关联域名列表
	ttl        time.Duration
}

type resolveResult struct {
	IPs       []string
	ResolveAt time.Time
	Err       error
}

func NewResolver() *Resolver {
	return &Resolver{
		cache:      make(map[string]*resolveResult),
		ipToDomain: make(map[string][]string),
		ttl:        30 * time.Second,
	}
}

// ResolveDomains 批量解析域名并更新 IP→域名 反查映射
func (r *Resolver) ResolveDomains(domains []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	newIPMap := make(map[string][]string)

	for _, domain := range domains {
		// 检查缓存是否有效
		if cached, ok := r.cache[domain]; ok && time.Since(cached.ResolveAt) < r.ttl {
			for _, ip := range cached.IPs {
				newIPMap[ip] = appendUnique(newIPMap[ip], domain)
			}
			continue
		}

		// DNS 解析，超时 3 秒
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		ips, err := net.DefaultResolver.LookupHost(ctx, domain)
		cancel()

		result := &resolveResult{
			ResolveAt: time.Now(),
			Err:       err,
		}
		if err == nil {
			result.IPs = ips
			for _, ip := range ips {
				newIPMap[ip] = appendUnique(newIPMap[ip], domain)
			}
		}
		r.cache[domain] = result
	}

	r.ipToDomain = newIPMap
}

// LookupDomainByIP 通过解析后的 IP 反查关联的域名 IOC
func (r *Resolver) LookupDomainByIP(ip string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ipToDomain[ip]
}

// GetResolvedIPs 获取某域名当前缓存的解析 IP
func (r *Resolver) GetResolvedIPs(domain string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if result, ok := r.cache[domain]; ok && result.Err == nil {
		return result.IPs
	}
	return nil
}

// MergeDNSCache 将系统 DNS 缓存中的 domain→IP 映射合并到 IP→域名 反查表
// 仅补充已在 IOC 列表中的域名对应的映射，不引入无关域名
func (r *Resolver) MergeDNSCache(dnsEntries map[string][]string, iocDomains map[string]struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for domain, ips := range dnsEntries {
		if _, isIOC := iocDomains[domain]; !isIOC {
			continue
		}
		for _, ip := range ips {
			r.ipToDomain[ip] = appendUnique(r.ipToDomain[ip], domain)
		}
	}
}

func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}
