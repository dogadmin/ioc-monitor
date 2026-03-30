package gui

import (
	"fmt"

	"github.com/lxn/walk"

	"iocmonitor/monitor"
)

// showHitAlert 弹出命中告警对话框
// 返回 true=继续监控, false=停止
func showHitAlert(owner walk.Form, hit monitor.HitRecord) bool {
	msg := fmt.Sprintf(
		"发现 IOC 命中！\n\n"+
			"时间: %s\n"+
			"IOC: %s (%s)\n"+
			"来源: %s\n"+
			"强度: %s\n"+
			"进程: %s (PID: %d)\n"+
			"远程: %s:%d\n"+
			"协议: %s\n\n"+
			"点击「是」继续监控，点击「否」停止并退出。",
		hit.Time.Format("2006-01-02 15:04:05"),
		hit.IOCValue,
		hit.IOCType.String(),
		hit.Source,
		hit.Strength.String(),
		orNA(hit.ProcessName),
		hit.PID,
		orNA(hit.RemoteAddr),
		hit.RemotePort,
		orNA(hit.Protocol),
	)

	ret := walk.MsgBox(owner, "IOC 命中告警", msg,
		walk.MsgBoxYesNo|walk.MsgBoxIconWarning|walk.MsgBoxTopMost)
	return ret == walk.DlgCmdYes
}

// showInfo 普通信息弹窗
func showInfo(owner walk.Form, title, msg string) {
	walk.MsgBox(owner, title, msg, walk.MsgBoxOK|walk.MsgBoxIconInformation)
}

// showError 错误弹窗
func showError(owner walk.Form, title, msg string) {
	walk.MsgBox(owner, title, msg, walk.MsgBoxOK|walk.MsgBoxIconError)
}

func orNA(s string) string {
	if s == "" {
		return "N/A"
	}
	return s
}
