package alert

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"iocmonitor/monitor"
)

// Logger 命中日志写入器，追加写入 res.txt
type Logger struct {
	mu       sync.Mutex
	filePath string
}

func NewLogger() *Logger {
	dir, _ := os.Getwd()
	exe, err := os.Executable()
	if err == nil {
		dir = filepath.Dir(exe)
	}
	return &Logger{filePath: filepath.Join(dir, "res.txt")}
}

// Write 将一条命中记录追加写入 res.txt（UTF-8，不覆盖旧内容）
func (l *Logger) Write(hit monitor.HitRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.OpenFile(l.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	record := fmt.Sprintf(`================================================================================
[命中记录]
命中时间:   %s
会话编号:   %s
IOC 类型:   %s
IOC 值:     %s
命中来源:   %s
命中强度:   %s
进程名:     %s
PID:        %d
父进程 PID: %s
命令行:     %s
当前用户:   %s
本地地址:   %s
本地端口:   %d
远程地址:   %s
远程端口:   %d
协议:       %s
连接状态:   %s
关联说明:   %s
================================================================================
`,
		hit.Time.Format("2006-01-02 15:04:05"),
		hit.SessionID,
		hit.IOCType.String(),
		hit.IOCValue,
		hit.Source,
		hit.Strength.String(),
		orNA(hit.ProcessName),
		hit.PID,
		i32OrNA(hit.ParentPID),
		orNA(hit.CmdLine),
		orNA(hit.Username),
		orNA(hit.LocalAddr),
		hit.LocalPort,
		orNA(hit.RemoteAddr),
		hit.RemotePort,
		orNA(hit.Protocol),
		orNA(hit.ConnState),
		orNA(hit.Note),
	)

	_, err = f.WriteString(record)
	return err
}

// FilePath 返回日志文件完整路径
func (l *Logger) FilePath() string {
	return l.filePath
}

func orNA(s string) string {
	if s == "" {
		return "N/A"
	}
	return s
}

func i32OrNA(v int32) string {
	if v == 0 {
		return "N/A"
	}
	return fmt.Sprintf("%d", v)
}
