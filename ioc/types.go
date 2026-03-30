package ioc

// IOCType IOC 分类类型
type IOCType int

const (
	IOCTypeIPv4   IOCType = iota // IPv4 地址
	IOCTypeIPv6                  // IPv6 地址
	IOCTypeDomain                // 域名
)

func (t IOCType) String() string {
	switch t {
	case IOCTypeIPv4:
		return "IPv4"
	case IOCTypeIPv6:
		return "IPv6"
	case IOCTypeDomain:
		return "域名"
	default:
		return "未知"
	}
}

// IOCEntry 单条 IOC 记录
type IOCEntry struct {
	Value    string  // 标准化后的值
	Type     IOCType // 类型
	Original string  // 用户原始输入
}
