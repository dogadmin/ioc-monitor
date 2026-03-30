package gui

import (
	"fmt"

	"github.com/lxn/walk"

	"iocmonitor/monitor"
)

// HitTableItem 命中表格的一行数据
type HitTableItem struct {
	Time     string
	IOCValue string
	IOCType  string
	Source   string
	Strength string
	Process  string
	PID      int32
	Remote   string
	Port     uint32
}

// HitTableModel 命中记录表格的数据模型
type HitTableModel struct {
	walk.TableModelBase
	items []*HitTableItem
}

func NewHitTableModel() *HitTableModel {
	return &HitTableModel{}
}

func (m *HitTableModel) RowCount() int {
	return len(m.items)
}

func (m *HitTableModel) Value(row, col int) interface{} {
	if row < 0 || row >= len(m.items) {
		return ""
	}
	item := m.items[row]
	switch col {
	case 0:
		return item.Time
	case 1:
		return item.IOCValue
	case 2:
		return item.IOCType
	case 3:
		return item.Source
	case 4:
		return item.Strength
	case 5:
		return item.Process
	case 6:
		return fmt.Sprintf("%d", item.PID)
	case 7:
		return item.Remote
	case 8:
		return fmt.Sprintf("%d", item.Port)
	}
	return ""
}

// AddHit 添加一条命中记录到表格顶部
func (m *HitTableModel) AddHit(hit monitor.HitRecord) {
	item := &HitTableItem{
		Time:     hit.Time.Format("15:04:05"),
		IOCValue: hit.IOCValue,
		IOCType:  hit.IOCType.String(),
		Source:   hit.Source,
		Strength: hit.Strength.String(),
		Process:  hit.ProcessName,
		PID:      hit.PID,
		Remote:   hit.RemoteAddr,
		Port:     hit.RemotePort,
	}
	// 插入到最前面，最新的在上面
	m.items = append([]*HitTableItem{item}, m.items...)
	m.PublishRowsReset()
}

// Clear 清空表格
func (m *HitTableModel) Clear() {
	m.items = nil
	m.PublishRowsReset()
}

// Count 返回记录数
func (m *HitTableModel) Count() int {
	return len(m.items)
}
