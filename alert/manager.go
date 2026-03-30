package alert

import (
	"fmt"
	"sync"
	"time"

	"iocmonitor/monitor"
)

// Manager 告警管理器
// 职责: 告警去重、文件日志写入、GUI日志回调、弹窗回调
type Manager struct {
	mu             sync.Mutex
	logger         *Logger
	dedupCache     map[string]time.Time  // 去重key -> 上次弹窗时间
	dedupWindow    time.Duration         // 去重时间窗口
	firstAlertOnly bool                  // 仅首次弹窗模式
	alertShown     map[string]struct{}   // firstAlertOnly 模式下已弹窗的 key
	hitCount       int64

	onGUILog func(string)
	onPopup  func(monitor.HitRecord) bool // 返回 true=继续, false=停止
}

func NewManager(logger *Logger) *Manager {
	return &Manager{
		logger:      logger,
		dedupCache:  make(map[string]time.Time),
		alertShown:  make(map[string]struct{}),
		dedupWindow: 10 * time.Second,
	}
}

// SetCallbacks 设置 GUI 回调
func (m *Manager) SetCallbacks(onGUILog func(string), onPopup func(monitor.HitRecord) bool) {
	m.onGUILog = onGUILog
	m.onPopup = onPopup
}

// SetFirstAlertOnly 切换"仅首次弹窗"模式
func (m *Manager) SetFirstAlertOnly(v bool) {
	m.mu.Lock()
	m.firstAlertOnly = v
	m.mu.Unlock()
}

// HandleHit 处理一条命中事件
// 返回 true=继续监控, false=用户要求停止
func (m *Manager) HandleHit(hit monitor.HitRecord) bool {
	m.mu.Lock()
	m.hitCount++

	// 文件日志（每次都写）
	if err := m.logger.Write(hit); err != nil {
		if m.onGUILog != nil {
			m.onGUILog(fmt.Sprintf("[错误] 写入日志失败: %v", err))
		}
	}

	// GUI 日志（每次都写）
	if m.onGUILog != nil {
		m.onGUILog(fmt.Sprintf("[命中] %s | %s (%s) | %s | 进程: %s (PID:%d) | %s",
			hit.Time.Format("15:04:05"),
			hit.IOCValue,
			hit.IOCType.String(),
			hit.Source,
			hit.ProcessName,
			hit.PID,
			hit.Strength.String(),
		))
	}

	// 去重判断：是否需要弹窗
	dedupKey := fmt.Sprintf("%s|%d|%s|%s", hit.IOCValue, hit.PID, hit.RemoteAddr, hit.Source)
	needPopup := true

	if m.firstAlertOnly {
		if _, shown := m.alertShown[dedupKey]; shown {
			needPopup = false
		} else {
			m.alertShown[dedupKey] = struct{}{}
		}
	} else {
		if lastTime, ok := m.dedupCache[dedupKey]; ok {
			if time.Since(lastTime) < m.dedupWindow {
				needPopup = false
			}
		}
	}

	if needPopup {
		m.dedupCache[dedupKey] = time.Now()
	}
	m.mu.Unlock()

	// 弹窗在锁外执行（阻塞等待用户点击）
	if needPopup && m.onPopup != nil {
		return m.onPopup(hit)
	}

	return true
}

// HitCount 返回累计命中次数
func (m *Manager) HitCount() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hitCount
}

// Reset 重置所有状态（新一轮监控前调用）
func (m *Manager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dedupCache = make(map[string]time.Time)
	m.alertShown = make(map[string]struct{})
	m.hitCount = 0
}
