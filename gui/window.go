package gui

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"

	"iocmonitor/alert"
	"iocmonitor/config"
	"iocmonitor/ioc"
	"iocmonitor/monitor"
)

// App 主应用结构，持有所有 GUI 组件和业务状态
type App struct {
	mainWindow *walk.MainWindow

	// IOC 输入区
	iocInput *walk.TextEdit

	// 控制区
	durationInput *walk.LineEdit
	startBtn      *walk.PushButton
	stopBtn       *walk.PushButton
	clearBtn      *walk.PushButton
	importBtn     *walk.PushButton
	exportBtn     *walk.PushButton
	clearLogBtn   *walk.PushButton

	// 选项
	chkFirstAlert *walk.CheckBox
	chkOpenRes    *walk.CheckBox
	chkDNS        *walk.CheckBox
	chkCmdLine    *walk.CheckBox
	chkHosts      *walk.CheckBox

	// 状态显示
	lblIOCCount      *walk.Label
	lblStatus        *walk.Label
	lblRemaining     *walk.Label
	lblElapsed       *walk.Label
	lblScanCount     *walk.Label
	lblHitCount      *walk.Label
	lblCurrentTime   *walk.Label
	lblSessionStart  *walk.Label

	// 命中表格
	hitTable *walk.TableView
	hitModel *HitTableModel

	// 日志区
	logOutput *walk.TextEdit

	// 状态栏
	sbiStatus *walk.StatusBarItem
	sbiIOC    *walk.StatusBarItem
	sbiHit    *walk.StatusBarItem

	// 业务对象
	engine      *monitor.Engine
	alertMgr    *alert.Manager
	alertLogger *alert.Logger
	cfg         *config.Config

	// UI 定时器
	clockTicker *time.Ticker
	clockDone   chan struct{}
}

// Run 创建并运行主窗口（阻塞直到窗口关闭）
func Run() {
	app := &App{
		hitModel:    NewHitTableModel(),
		alertLogger: alert.NewLogger(),
		cfg:         config.Load(),
	}
	app.alertMgr = alert.NewManager(app.alertLogger)

	var mw *walk.MainWindow

	err := MainWindow{
		AssignTo: &mw,
		Title:    "IOC 监控工具",
		MinSize:  Size{Width: 900, Height: 700},
		Size:     Size{Width: 1000, Height: 780},
		Layout:   VBox{MarginsZero: false},
		Children: []Widget{
			// ===== 上半部分: IOC输入 + 控制面板 =====
			Composite{
				Layout:  HBox{},
				Children: []Widget{
					// 左侧: IOC 输入
					GroupBox{
						Title:  "IOC 输入 (一行一个域名/IP)",
						Layout: VBox{},
						Children: []Widget{
							TextEdit{
								AssignTo: &app.iocInput,
								VScroll:  true,
								MinSize:  Size{Width: 400, Height: 180},
							},
						},
					},
					// 右侧: 控制面板
					GroupBox{
						Title:  "控制面板",
						Layout: VBox{},
						MinSize: Size{Width: 320},
						Children: []Widget{
							// 监控时长
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									Label{Text: "监控时长(秒):"},
									LineEdit{AssignTo: &app.durationInput, MinSize: Size{Width: 80}},
								},
							},
							// 按钮行1
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									PushButton{AssignTo: &app.startBtn, Text: "开始监控"},
									PushButton{AssignTo: &app.stopBtn, Text: "停止", Enabled: false},
									PushButton{AssignTo: &app.clearBtn, Text: "清空IOC"},
								},
							},
							// 按钮行2
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									PushButton{AssignTo: &app.importBtn, Text: "导入IOC"},
									PushButton{AssignTo: &app.exportBtn, Text: "导出IOC"},
									PushButton{AssignTo: &app.clearLogBtn, Text: "清空日志"},
								},
							},
							// 分隔
							VSpacer{Size: 4},
							// 状态信息
							Composite{
								Layout: Grid{Columns: 2, MarginsZero: true},
								Children: []Widget{
									Label{Text: "IOC 数量:"},
									Label{AssignTo: &app.lblIOCCount, Text: "0"},
									Label{Text: "状态:"},
									Label{AssignTo: &app.lblStatus, Text: "未开始"},
									Label{Text: "剩余时间:"},
									Label{AssignTo: &app.lblRemaining, Text: "-"},
									Label{Text: "已运行:"},
									Label{AssignTo: &app.lblElapsed, Text: "-"},
									Label{Text: "扫描次数:"},
									Label{AssignTo: &app.lblScanCount, Text: "0"},
									Label{Text: "命中次数:"},
									Label{AssignTo: &app.lblHitCount, Text: "0"},
									Label{Text: "当前时间:"},
									Label{AssignTo: &app.lblCurrentTime, Text: "-"},
									Label{Text: "会话开始:"},
									Label{AssignTo: &app.lblSessionStart, Text: "-"},
								},
							},
							VSpacer{Size: 4},
							// 选项
							CheckBox{AssignTo: &app.chkFirstAlert, Text: "仅首次弹窗(后续仅写日志)"},
							CheckBox{AssignTo: &app.chkOpenRes, Text: "停止后自动打开 res.txt"},
							CheckBox{AssignTo: &app.chkDNS, Text: "检查 DNS 缓存", Checked: true},
							CheckBox{AssignTo: &app.chkCmdLine, Text: "检查进程命令行", Checked: true},
							CheckBox{AssignTo: &app.chkHosts, Text: "检查 hosts 文件", Checked: true},
						},
					},
				},
			},
			// ===== 命中记录表格 =====
			GroupBox{
				Title:  "命中记录",
				Layout: VBox{},
				Children: []Widget{
					TableView{
						AssignTo:         &app.hitTable,
						AlternatingRowBG: true,
						ColumnsOrderable: true,
						MinSize:          Size{Height: 120},
						Model:            app.hitModel,
						Columns: []TableViewColumn{
							{Title: "时间", Width: 70},
							{Title: "IOC", Width: 160},
							{Title: "类型", Width: 45},
							{Title: "来源", Width: 110},
							{Title: "强度", Width: 55},
							{Title: "进程", Width: 110},
							{Title: "PID", Width: 55},
							{Title: "远程地址", Width: 120},
							{Title: "端口", Width: 50},
						},
					},
				},
			},
			// ===== 实时日志 =====
			GroupBox{
				Title:  "实时日志",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{
						AssignTo: &app.logOutput,
						ReadOnly: true,
						VScroll:  true,
						MinSize:  Size{Height: 120},
					},
				},
			},
		},
		StatusBarItems: []StatusBarItem{
			{AssignTo: &app.sbiStatus, Text: "就绪", Width: 200},
			{AssignTo: &app.sbiIOC, Text: "IOC: 0", Width: 100},
			{AssignTo: &app.sbiHit, Text: "命中: 0", Width: 100},
		},
	}.Create()

	if err != nil {
		fmt.Fprintf(os.Stderr, "创建窗口失败: %v\n", err)
		os.Exit(1)
	}

	app.mainWindow = mw
	app.initFromConfig()
	app.bindEvents()
	app.startClock()

	mw.Run()

	// 窗口关闭时清理
	app.stopClock()
	if app.engine != nil && app.engine.IsRunning() {
		app.engine.Stop()
	}
	app.saveConfig()
}

// initFromConfig 从配置恢复上次状态
func (app *App) initFromConfig() {
	if app.cfg.LastIOCs != "" {
		app.iocInput.SetText(app.cfg.LastIOCs)
	}
	app.durationInput.SetText(strconv.Itoa(app.cfg.LastDuration))
	app.chkFirstAlert.SetChecked(app.cfg.FirstAlertOnly)
	app.chkOpenRes.SetChecked(app.cfg.OpenResOnStop)
	app.chkDNS.SetChecked(app.cfg.CheckDNSCache)
	app.chkCmdLine.SetChecked(app.cfg.CheckCmdLine)
	app.chkHosts.SetChecked(app.cfg.CheckHosts)

	// 更新 IOC 计数
	app.updateIOCCount()
}

// saveConfig 保存当前状态到配置
func (app *App) saveConfig() {
	app.cfg.LastIOCs = app.iocInput.Text()
	dur, err := strconv.Atoi(strings.TrimSpace(app.durationInput.Text()))
	if err == nil && dur > 0 {
		app.cfg.LastDuration = dur
	}
	app.cfg.FirstAlertOnly = app.chkFirstAlert.Checked()
	app.cfg.OpenResOnStop = app.chkOpenRes.Checked()
	app.cfg.CheckDNSCache = app.chkDNS.Checked()
	app.cfg.CheckCmdLine = app.chkCmdLine.Checked()
	app.cfg.CheckHosts = app.chkHosts.Checked()
	_ = app.cfg.Save()
}

// bindEvents 绑定所有按钮事件
func (app *App) bindEvents() {
	app.startBtn.Clicked().Attach(app.onStart)
	app.stopBtn.Clicked().Attach(app.onStop)
	app.clearBtn.Clicked().Attach(app.onClearIOC)
	app.importBtn.Clicked().Attach(app.onImportIOC)
	app.exportBtn.Clicked().Attach(app.onExportIOC)
	app.clearLogBtn.Clicked().Attach(app.onClearLog)

	app.chkFirstAlert.CheckedChanged().Attach(func() {
		if app.alertMgr != nil {
			app.alertMgr.SetFirstAlertOnly(app.chkFirstAlert.Checked())
		}
	})

	// IOC 输入变化时更新计数
	app.iocInput.TextChanged().Attach(app.updateIOCCount)
}

// startClock 启动界面时钟（每秒更新当前时间）
func (app *App) startClock() {
	app.clockTicker = time.NewTicker(1 * time.Second)
	app.clockDone = make(chan struct{})
	go func() {
		for {
			select {
			case <-app.clockDone:
				return
			case <-app.clockTicker.C:
				app.mainWindow.Synchronize(func() {
					app.lblCurrentTime.SetText(time.Now().Format("2006-01-02 15:04:05"))
				})
			}
		}
	}()
}

func (app *App) stopClock() {
	if app.clockTicker != nil {
		app.clockTicker.Stop()
	}
	if app.clockDone != nil {
		close(app.clockDone)
	}
}

// updateIOCCount 刷新 IOC 数量显示
func (app *App) updateIOCCount() {
	text := app.iocInput.Text()
	set := ioc.Parse(text)
	count := set.Count()
	app.lblIOCCount.SetText(strconv.Itoa(count))
	app.sbiIOC.SetText(fmt.Sprintf("IOC: %d", count))
}

// appendLog 追加一条日志到实时日志区
func (app *App) appendLog(msg string) {
	app.mainWindow.Synchronize(func() {
		if app.logOutput.TextLength() > 0 {
			app.logOutput.AppendText("\r\n" + msg)
		} else {
			app.logOutput.AppendText(msg)
		}
	})
}

// setMonitoringUI 设置监控中的 UI 状态
func (app *App) setMonitoringUI(running bool) {
	app.mainWindow.Synchronize(func() {
		app.startBtn.SetEnabled(!running)
		app.stopBtn.SetEnabled(running)
		app.iocInput.SetEnabled(!running)
		app.durationInput.SetEnabled(!running)
		app.importBtn.SetEnabled(!running)
		app.clearBtn.SetEnabled(!running)
		app.chkDNS.SetEnabled(!running)
		app.chkCmdLine.SetEnabled(!running)
		app.chkHosts.SetEnabled(!running)

		if running {
			app.lblStatus.SetText("监控中")
			app.sbiStatus.SetText("监控中...")
		} else {
			app.lblStatus.SetText("已停止")
			app.sbiStatus.SetText("就绪")
		}
	})
}

// ===== 按钮事件处理 =====

func (app *App) onStart() {
	// 解析 IOC
	text := app.iocInput.Text()
	iocSet := ioc.Parse(text)
	if iocSet.Count() == 0 {
		showError(app.mainWindow, "错误", "请输入至少一个 IOC (域名或IP)")
		return
	}

	// 解析时长
	durStr := strings.TrimSpace(app.durationInput.Text())
	duration, err := strconv.Atoi(durStr)
	if err != nil || duration <= 0 {
		showError(app.mainWindow, "错误", "请输入有效的监控时长（正整数，单位：秒）")
		return
	}

	// 重置告警管理器
	app.alertMgr.Reset()
	app.alertMgr.SetFirstAlertOnly(app.chkFirstAlert.Checked())

	// 设置告警回调
	app.alertMgr.SetCallbacks(
		// GUI 日志
		func(msg string) { app.appendLog(msg) },
		// 弹窗（在 UI 线程执行）
		func(hit monitor.HitRecord) bool {
			result := make(chan bool, 1)
			app.mainWindow.Synchronize(func() {
				result <- showHitAlert(app.mainWindow, hit)
			})
			return <-result
		},
	)

	// 引擎回调
	callbacks := monitor.EngineCallbacks{
		OnHit: func(hit monitor.HitRecord) bool {
			// 更新命中表格
			app.mainWindow.Synchronize(func() {
				app.hitModel.AddHit(hit)
				count := app.alertMgr.HitCount()
				app.lblHitCount.SetText(strconv.FormatInt(count, 10))
				app.sbiHit.SetText(fmt.Sprintf("命中: %d", count))
			})
			return app.alertMgr.HandleHit(hit)
		},
		OnLog: func(msg string) {
			app.appendLog(msg)
		},
		OnTick: func(elapsed, remaining int, scanCount int64) {
			app.mainWindow.Synchronize(func() {
				app.lblElapsed.SetText(fmt.Sprintf("%d 秒", elapsed))
				app.lblRemaining.SetText(fmt.Sprintf("%d 秒", remaining))
				app.lblScanCount.SetText(strconv.FormatInt(scanCount, 10))
			})
		},
		OnFinish: func() {
			app.setMonitoringUI(false)
			app.appendLog(fmt.Sprintf("[%s] 监控结束", time.Now().Format("15:04:05")))
			app.mainWindow.Synchronize(func() {
				app.lblStatus.SetText("监控结束")
				app.lblRemaining.SetText("0 秒")
				showInfo(app.mainWindow, "监控结束", "本轮监控已结束。")

				if app.chkOpenRes.Checked() {
					exec.Command("cmd", "/c", "start", "", app.alertLogger.FilePath()).Start()
				}
			})
			app.saveConfig()
		},
	}

	// 创建并启动引擎
	app.engine = monitor.NewEngine(
		iocSet, duration, callbacks,
		app.chkDNS.Checked(), app.chkCmdLine.Checked(), app.chkHosts.Checked(),
	)

	app.setMonitoringUI(true)
	app.lblSessionStart.SetText(time.Now().Format("2006-01-02 15:04:05"))
	app.hitModel.Clear()

	app.engine.Start()
}

func (app *App) onStop() {
	if app.engine != nil && app.engine.IsRunning() {
		app.engine.Stop()
	}
}

func (app *App) onClearIOC() {
	app.iocInput.SetText("")
}

func (app *App) onClearLog() {
	app.logOutput.SetText("")
	app.hitModel.Clear()
	app.lblHitCount.SetText("0")
	app.sbiHit.SetText("命中: 0")
}

func (app *App) onImportIOC() {
	dlg := new(walk.FileDialog)
	dlg.Title = "导入 IOC 文件"
	dlg.Filter = "文本文件 (*.txt)|*.txt|所有文件 (*.*)|*.*"

	if ok, _ := dlg.ShowOpen(app.mainWindow); !ok {
		return
	}

	data, err := os.ReadFile(dlg.FilePath)
	if err != nil {
		showError(app.mainWindow, "导入失败", fmt.Sprintf("读取文件失败: %v", err))
		return
	}

	// 合并到现有输入
	current := strings.TrimSpace(app.iocInput.Text())
	newContent := strings.TrimSpace(string(data))
	if current != "" && newContent != "" {
		current += "\n"
	}
	app.iocInput.SetText(current + newContent)
	app.appendLog(fmt.Sprintf("[%s] 已导入 IOC 文件: %s", time.Now().Format("15:04:05"), dlg.FilePath))
}

func (app *App) onExportIOC() {
	text := app.iocInput.Text()
	iocSet := ioc.Parse(text)
	if iocSet.Count() == 0 {
		showError(app.mainWindow, "导出失败", "没有可导出的 IOC")
		return
	}

	dlg := new(walk.FileDialog)
	dlg.Title = "导出 IOC 列表"
	dlg.Filter = "文本文件 (*.txt)|*.txt"

	if ok, _ := dlg.ShowSave(app.mainWindow); !ok {
		return
	}

	filePath := dlg.FilePath
	if !strings.HasSuffix(strings.ToLower(filePath), ".txt") {
		filePath += ".txt"
	}

	err := os.WriteFile(filePath, []byte(iocSet.Text()), 0644)
	if err != nil {
		showError(app.mainWindow, "导出失败", fmt.Sprintf("写入文件失败: %v", err))
		return
	}

	app.appendLog(fmt.Sprintf("[%s] 已导出 %d 条 IOC 到: %s",
		time.Now().Format("15:04:05"), iocSet.Count(), filePath))
}
