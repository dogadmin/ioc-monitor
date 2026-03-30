package monitor

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"iocmonitor/ioc"
)

// Engine 监控引擎：启动后每秒执行一次 采集→匹配→告警 循环
type Engine struct {
	iocSet    *ioc.IOCSet
	resolver  *ioc.Resolver
	collector *Collector
	matcher   *Matcher
	callbacks EngineCallbacks

	ctx    context.Context
	cancel context.CancelFunc

	sessionID string
	duration  int // 监控时长(秒)
	scanCount int64
	running   int32 // 0=停止 1=运行 (atomic)

	checkDNS   bool
	checkCmd   bool
	checkHosts bool

	domainSet map[string]struct{} // 域名IOC集合，启动时构建一次
}

func NewEngine(iocSet *ioc.IOCSet, duration int, cb EngineCallbacks,
	checkDNS, checkCmd, checkHosts bool) *Engine {

	sessionID := fmt.Sprintf("SESSION-%s", time.Now().Format("20060102-150405"))
	resolver := ioc.NewResolver()

	return &Engine{
		iocSet:     iocSet,
		resolver:   resolver,
		collector:  NewCollector(checkDNS, checkHosts),
		callbacks:  cb,
		sessionID:  sessionID,
		duration:   duration,
		checkDNS:   checkDNS,
		checkCmd:   checkCmd,
		checkHosts: checkHosts,
	}
}

// Start 启动监控（非阻塞，后台 goroutine）
func (e *Engine) Start() {
	if !atomic.CompareAndSwapInt32(&e.running, 0, 1) {
		return
	}

	e.ctx, e.cancel = context.WithCancel(context.Background())
	e.matcher = NewMatcher(e.iocSet, e.resolver, e.sessionID, e.checkCmd)
	atomic.StoreInt64(&e.scanCount, 0)

	// 构建域名集合（仅一次）
	domains := e.iocSet.GetDomains()
	e.domainSet = make(map[string]struct{}, len(domains))
	for _, d := range domains {
		e.domainSet[d] = struct{}{}
	}

	// 初始解析域名 IOC
	if len(domains) > 0 {
		e.log("正在解析域名 IOC...")
		e.resolver.ResolveDomains(domains)
		e.log(fmt.Sprintf("域名解析完成，共 %d 个域名", len(domains)))
	}

	e.log(fmt.Sprintf("监控开始 | 会话: %s | 时长: %d秒 | IOC数量: %d",
		e.sessionID, e.duration, e.iocSet.Count()))

	go e.loop()
}

// Stop 手动停止监控
func (e *Engine) Stop() {
	if atomic.CompareAndSwapInt32(&e.running, 1, 0) {
		if e.cancel != nil {
			e.cancel()
		}
	}
}

// IsRunning 是否正在运行
func (e *Engine) IsRunning() bool {
	return atomic.LoadInt32(&e.running) == 1
}

// ScanCount 已完成的扫描轮次
func (e *Engine) ScanCount() int64 {
	return atomic.LoadInt64(&e.scanCount)
}

// SessionID 当前会话标识
func (e *Engine) SessionID() string {
	return e.sessionID
}

// loop 监控主循环
func (e *Engine) loop() {
	defer func() {
		atomic.StoreInt32(&e.running, 0)
		if e.callbacks.OnFinish != nil {
			e.callbacks.OnFinish()
		}
	}()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	dnsRefresh := time.NewTicker(30 * time.Second)
	defer dnsRefresh.Stop()

	startTime := time.Now()
	deadline := startTime.Add(time.Duration(e.duration) * time.Second)

	for {
		select {
		case <-e.ctx.Done():
			e.log("监控已手动停止")
			return

		case <-dnsRefresh.C:
			// 定期刷新域名解析缓存
			if domains := e.iocSet.GetDomains(); len(domains) > 0 {
				e.resolver.ResolveDomains(domains)
			}

		case <-ticker.C:
			if time.Now().After(deadline) {
				e.log("监控时间到，自动停止")
				return
			}

			count := atomic.AddInt64(&e.scanCount, 1)
			elapsed := int(time.Since(startTime).Seconds())
			remaining := e.duration - elapsed
			if remaining < 0 {
				remaining = 0
			}

			// 通知 GUI 刷新计时
			if e.callbacks.OnTick != nil {
				e.callbacks.OnTick(elapsed, remaining, count)
			}

			// 采集系统快照
			snap := e.collector.Collect(e.ctx)
			for _, errMsg := range snap.Errors {
				e.log("[警告] " + errMsg)
			}

			// DNS 缓存不单独作为命中源，而是补充 resolver 的 IP→域名 映射
			// 这样当某个连接的远程 IP 恰好在 DNS 缓存中关联了域名 IOC，才算有实际连接的命中
			if len(snap.DNSCache) > 0 {
				dnsMap := make(map[string][]string, len(snap.DNSCache))
				for _, entry := range snap.DNSCache {
					dnsMap[entry.Domain] = entry.IPs
				}
				e.resolver.MergeDNSCache(dnsMap, e.domainSet)
			}

			// IOC 匹配
			hits := e.matcher.Match(snap)

			// 处理每条命中
			for _, hit := range hits {
				if e.callbacks.OnHit != nil {
					shouldContinue := e.callbacks.OnHit(hit)
					if !shouldContinue {
						e.log("用户选择停止监控")
						return
					}
				}
				if !e.IsRunning() {
					return
				}
			}
		}
	}
}

func (e *Engine) log(msg string) {
	if e.callbacks.OnLog != nil {
		e.callbacks.OnLog(fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg))
	}
}
