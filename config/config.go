package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config 程序配置，持久化到 config.json
type Config struct {
	LastIOCs       string `json:"last_iocs"`        // 上次输入的 IOC
	LastDuration   int    `json:"last_duration"`     // 上次监控时长
	FirstAlertOnly bool   `json:"first_alert_only"`  // 仅首次弹窗
	OpenResOnStop  bool   `json:"open_res_on_stop"`  // 停止后自动打开 res.txt
	CheckDNSCache  bool   `json:"check_dns_cache"`   // 检查 DNS 缓存
	CheckCmdLine   bool   `json:"check_cmdline"`     // 检查进程命令行
	CheckHosts     bool   `json:"check_hosts"`       // 检查 hosts 文件
}

// Default 返回默认配置
func Default() *Config {
	return &Config{
		LastDuration:   60,
		FirstAlertOnly: false,
		OpenResOnStop:  false,
		CheckDNSCache:  true,
		CheckCmdLine:   true,
		CheckHosts:     true,
	}
}

func configPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "config.json"
	}
	return filepath.Join(filepath.Dir(exe), "config.json")
}

// Load 从文件加载配置，失败则返回默认值
func Load() *Config {
	cfg := Default()
	data, err := os.ReadFile(configPath())
	if err != nil {
		return cfg
	}
	_ = json.Unmarshal(data, cfg)
	// 兜底
	if cfg.LastDuration <= 0 {
		cfg.LastDuration = 60
	}
	return cfg
}

// Save 保存配置到文件
func (c *Config) Save() error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath(), data, 0644)
}
