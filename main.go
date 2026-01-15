package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	iphlpapi                       = syscall.NewLazyDLL("iphlpapi.dll")
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	psapi                          = syscall.NewLazyDLL("psapi.dll")
	ntdll                          = syscall.NewLazyDLL("ntdll.dll")
	procGetExtendedTcpTable        = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable        = iphlpapi.NewProc("GetExtendedUdpTable")
	procOpenProcess                = kernel32.NewProc("OpenProcess")
	procCloseHandle                = kernel32.NewProc("CloseHandle")
	procGetModuleBaseNameW         = psapi.NewProc("GetModuleBaseNameW")
	procQueryFullProcessImageNameW = kernel32.NewProc("QueryFullProcessImageNameW")
	procNtQueryInformationProcess  = ntdll.NewProc("NtQueryInformationProcess")
)

const (
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_READ           = 0x0010
)

type MIB_TCPROW_OWNER_PID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

type MIB_UDPROW_OWNER_PID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

type Monitor struct {
	iocList   []string
	iocIPs    map[string]bool
	ipToIOC   map[string]string
	iocMutex  sync.RWMutex
	duration  int
	hitCount  int
	seenConns map[string]bool
	seenMutex sync.Mutex
	stop      bool
}

func main() {
	fmt.Println("====================================")
	fmt.Println("  IOC 网络连接监控工具")
	fmt.Println("  IOC Network Connection Monitor")
	fmt.Println("====================================")
	fmt.Println("  需要管理员权限运行")
	fmt.Println("====================================")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("选择输入方式:")
	fmt.Println("  1. 手动输入单个 IOC")
	fmt.Println("  2. 从文件批量读取 IOC")
	fmt.Print("请选择 (1/2, 默认 1): ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	var iocList []string

	if choice == "2" {
		fmt.Print("输入 IOC 文件路径: ")
		filePath, _ := reader.ReadString('\n')
		filePath = strings.TrimSpace(filePath)
		if filePath == "" {
			fmt.Println("错误: 文件路径不能为空")
			waitExit()
			return
		}

		var err error
		iocList, err = readIOCFile(filePath)
		if err != nil {
			fmt.Printf("错误: 读取文件失败 - %v\n", err)
			waitExit()
			return
		}
		if len(iocList) == 0 {
			fmt.Println("错误: 文件中没有有效的 IOC")
			waitExit()
			return
		}
		fmt.Printf("从文件读取到 %d 个 IOC\n", len(iocList))
	} else {
		fmt.Print("输入 IOC (IP 或域名): ")
		ioc, _ := reader.ReadString('\n')
		ioc = strings.TrimSpace(ioc)
		if ioc == "" {
			fmt.Println("错误: IOC 不能为空")
			waitExit()
			return
		}
		iocList = []string{ioc}
	}

	fmt.Print("输入监控时长 (秒, 默认 60): ")
	durStr, _ := reader.ReadString('\n')
	durStr = strings.TrimSpace(durStr)
	duration := 60
	if durStr != "" {
		if d, err := strconv.Atoi(durStr); err == nil && d > 0 {
			duration = d
		}
	}

	m := &Monitor{
		iocList:   iocList,
		iocIPs:    make(map[string]bool),
		ipToIOC:   make(map[string]string),
		seenConns: make(map[string]bool),
		duration:  duration,
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n\n收到停止信号...")
		m.stop = true
	}()

	fmt.Println("\n正在解析 IOC...")
	m.resolveAllIOC()

	if len(m.iocIPs) == 0 {
		fmt.Println("错误: 没有有效的 IP 可供监控")
		waitExit()
		return
	}

	fmt.Printf("共 %d 个 IOC, 解析到 %d 个 IP\n", len(iocList), len(m.iocIPs))

	fmt.Println()
	fmt.Printf("开始监控, 时长 %d 秒, 按 Ctrl+C 停止\n", duration)
	fmt.Println("------------------------------------")

	m.run()

	fmt.Println("------------------------------------")
	fmt.Printf("监控结束, 共命中 %d 次\n", m.hitCount)
	if m.hitCount > 0 {
		fmt.Println("结果已保存到 res.txt")
	}
	waitExit()
}

func readIOCFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var iocs []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.Split(line, "#")[0]
		line = strings.TrimSpace(line)

		ioc := cleanIOC(line)
		if ioc != "" && !seen[ioc] {
			seen[ioc] = true
			iocs = append(iocs, ioc)
		}
	}
	return iocs, scanner.Err()
}

func cleanIOC(input string) string {
	input = strings.TrimSpace(input)

	input = strings.TrimPrefix(input, "http://")
	input = strings.TrimPrefix(input, "https://")
	input = strings.TrimPrefix(input, "ftp://")

	if idx := strings.Index(input, "/"); idx != -1 {
		input = input[:idx]
	}

	if strings.Contains(input, ":") && !strings.Contains(input, "[") {
		if host, _, err := net.SplitHostPort(input); err == nil {
			input = host
		}
	}

	input = strings.Trim(input, "[]")

	return strings.TrimSpace(input)
}

func (m *Monitor) resolveAllIOC() {
	for _, ioc := range m.iocList {
		if isValidIP(ioc) {
			m.iocMutex.Lock()
			m.iocIPs[ioc] = true
			m.ipToIOC[ioc] = ioc
			m.iocMutex.Unlock()
			fmt.Printf("  [IP] %s\n", ioc)
		} else {
			ips, err := net.LookupIP(ioc)
			if err != nil {
				fmt.Printf("  [域名] %s -> 解析失败: %v\n", ioc, err)
				continue
			}
			m.iocMutex.Lock()
			for _, ip := range ips {
				ipStr := ip.String()
				m.iocIPs[ipStr] = true
				m.ipToIOC[ipStr] = ioc
			}
			m.iocMutex.Unlock()
			var ipStrs []string
			for _, ip := range ips {
				ipStrs = append(ipStrs, ip.String())
			}
			fmt.Printf("  [域名] %s -> %v\n", ioc, ipStrs)
		}
	}
}

func waitExit() {
	fmt.Println("\n按回车键退出...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

func (m *Monitor) run() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	dnsTicker := time.NewTicker(30 * time.Second)
	defer dnsTicker.Stop()

	remaining := m.duration
	lastPrint := time.Now()

	for remaining > 0 && !m.stop {
		select {
		case <-ticker.C:
			remaining--

			if time.Since(lastPrint) >= time.Second {
				fmt.Printf("\r[%s] 剩余 %d 秒 | IOC: %d | IP: %d | 命中: %d",
					time.Now().Format("15:04:05"), remaining, len(m.iocList), len(m.iocIPs), m.hitCount)
				lastPrint = time.Now()
			}

			m.checkConnections()
		case <-dnsTicker.C:
			m.refreshDNS()
		}
	}
	fmt.Println()
}

func (m *Monitor) refreshDNS() {
	for _, ioc := range m.iocList {
		if !isValidIP(ioc) {
			ips, err := net.LookupIP(ioc)
			if err != nil {
				continue
			}
			m.iocMutex.Lock()
			for _, ip := range ips {
				ipStr := ip.String()
				m.iocIPs[ipStr] = true
				m.ipToIOC[ipStr] = ioc
			}
			m.iocMutex.Unlock()
		}
	}
}

func (m *Monitor) checkConnections() {
	m.iocMutex.RLock()
	iocIPs := make(map[string]bool)
	for k, v := range m.iocIPs {
		iocIPs[k] = v
	}
	m.iocMutex.RUnlock()

	m.checkTCP(iocIPs)
	m.checkUDP(iocIPs)
}

func (m *Monitor) checkTCP(iocIPs map[string]bool) {
	var size uint32 = 0
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, 2, 5, 0)
	if size == 0 {
		return
	}

	buf := make([]byte, size)
	ret, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1, 2, 5, 0,
	)
	if ret != 0 {
		return
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rows := buf[4:]

	for i := uint32(0); i < numEntries; i++ {
		row := (*MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&rows[i*24]))
		remoteIP := uint32ToIP(row.RemoteAddr)

		if iocIPs[remoteIP] {
			remotePort := ntohs(uint16(row.RemotePort))
			localIP := uint32ToIP(row.LocalAddr)
			localPort := ntohs(uint16(row.LocalPort))
			status := tcpStateToString(row.State)
			pid := row.OwningPid

			connKey := fmt.Sprintf("tcp-%s:%d-%d-%s", remoteIP, remotePort, pid, status)
			m.seenMutex.Lock()
			if m.seenConns[connKey] {
				m.seenMutex.Unlock()
				continue
			}
			m.seenConns[connKey] = true
			m.seenMutex.Unlock()

			m.recordHit("TCP", status, remoteIP, remotePort, localIP, localPort, pid)
		}
	}
}

func (m *Monitor) checkUDP(iocIPs map[string]bool) {
	var size uint32 = 0
	procGetExtendedUdpTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, 2, 1, 0)
	if size == 0 {
		return
	}

	buf := make([]byte, size)
	ret, _, _ := procGetExtendedUdpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1, 2, 1, 0,
	)
	if ret != 0 {
		return
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rows := buf[4:]

	for i := uint32(0); i < numEntries; i++ {
		row := (*MIB_UDPROW_OWNER_PID)(unsafe.Pointer(&rows[i*12]))
		localIP := uint32ToIP(row.LocalAddr)
		localPort := ntohs(uint16(row.LocalPort))
		pid := row.OwningPid

		if iocIPs[localIP] {
			connKey := fmt.Sprintf("udp-%s:%d-%d", localIP, localPort, pid)
			m.seenMutex.Lock()
			if m.seenConns[connKey] {
				m.seenMutex.Unlock()
				continue
			}
			m.seenConns[connKey] = true
			m.seenMutex.Unlock()

			m.recordHit("UDP", "-", localIP, localPort, "", 0, pid)
		}
	}
}

func (m *Monitor) recordHit(proto, status, remoteIP string, remotePort uint16, localIP string, localPort uint16, pid uint32) {
	m.hitCount++

	m.iocMutex.RLock()
	ioc := m.ipToIOC[remoteIP]
	m.iocMutex.RUnlock()
	if ioc == "" {
		ioc = remoteIP
	}

	procName, procPath, _ := getProcessInfo(pid)
	parentInfo := getParentProcessChain(pid)

	fmt.Printf("\n\n[命中] %s IOC:%s %s/%s %s:%d -> PID:%d %s\n",
		time.Now().Format("15:04:05"), ioc, proto, status, remoteIP, remotePort, pid, procName)

	output := m.formatOutput(proto, status, remoteIP, remotePort, localIP, localPort, pid, procName, procPath, parentInfo, ioc)
	m.writeToFile(output)
}

func (m *Monitor) formatOutput(proto, status, remoteIP string, remotePort uint16, localIP string, localPort uint16, pid uint32, procName, procPath string, parentInfo []string, ioc string) string {
	var sb strings.Builder
	sb.WriteString("\n================================================================================\n")
	sb.WriteString(fmt.Sprintf("时间戳: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("IOC: %s\n", ioc))
	sb.WriteString(fmt.Sprintf("协议: %s\n", proto))
	sb.WriteString(fmt.Sprintf("状态: %s\n", status))
	sb.WriteString(fmt.Sprintf("远程地址: %s:%d\n", remoteIP, remotePort))
	if localIP != "" {
		sb.WriteString(fmt.Sprintf("本地地址: %s:%d\n", localIP, localPort))
	}
	sb.WriteString("--------------------------------------------------------------------------------\n")
	sb.WriteString("[命中进程]\n")
	sb.WriteString(fmt.Sprintf("  PID: %d\n", pid))
	sb.WriteString(fmt.Sprintf("  进程名: %s\n", procName))
	sb.WriteString(fmt.Sprintf("  路径: %s\n", procPath))

	for i, info := range parentInfo {
		sb.WriteString(fmt.Sprintf("[父进程 %d]\n", i+1))
		sb.WriteString(info)
	}
	sb.WriteString("================================================================================\n")
	return sb.String()
}

func (m *Monitor) writeToFile(content string) {
	f, err := os.OpenFile("res.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(content)
}

func isValidIP(input string) bool {
	return net.ParseIP(input) != nil
}

func uint32ToIP(addr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		addr&0xFF,
		(addr>>8)&0xFF,
		(addr>>16)&0xFF,
		(addr>>24)&0xFF)
}

func ntohs(n uint16) uint16 {
	return (n>>8)&0xFF | (n&0xFF)<<8
}

func tcpStateToString(state uint32) string {
	states := map[uint32]string{
		1:  "CLOSED",
		2:  "LISTEN",
		3:  "SYN_SENT",
		4:  "SYN_RCVD",
		5:  "ESTABLISHED",
		6:  "FIN_WAIT1",
		7:  "FIN_WAIT2",
		8:  "CLOSE_WAIT",
		9:  "CLOSING",
		10: "LAST_ACK",
		11: "TIME_WAIT",
		12: "DELETE_TCB",
	}
	if s, ok := states[state]; ok {
		return s
	}
	return fmt.Sprintf("UNKNOWN(%d)", state)
}

func getProcessInfo(pid uint32) (name, path, cmdline string) {
	handle, _, _ := procOpenProcess.Call(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, 0, uintptr(pid))
	if handle == 0 {
		return fmt.Sprintf("PID_%d", pid), "", ""
	}
	defer procCloseHandle.Call(handle)

	nameBuf := make([]uint16, 260)
	ret, _, _ := procGetModuleBaseNameW.Call(handle, 0, uintptr(unsafe.Pointer(&nameBuf[0])), 260)
	if ret > 0 {
		name = syscall.UTF16ToString(nameBuf)
	} else {
		name = fmt.Sprintf("PID_%d", pid)
	}

	pathBuf := make([]uint16, 1024)
	pathSize := uint32(1024)
	ret, _, _ = procQueryFullProcessImageNameW.Call(handle, 0, uintptr(unsafe.Pointer(&pathBuf[0])), uintptr(unsafe.Pointer(&pathSize)))
	if ret != 0 {
		path = syscall.UTF16ToString(pathBuf)
	}

	return
}

func getParentProcessChain(pid uint32) []string {
	var chain []string
	currentPid := pid
	visited := make(map[uint32]bool)

	for i := 0; i < 10; i++ {
		ppid := getParentPID(currentPid)
		if ppid == 0 || ppid == currentPid || visited[ppid] {
			break
		}
		visited[ppid] = true

		name, path, _ := getProcessInfo(ppid)
		info := fmt.Sprintf("  PID: %d\n  进程名: %s\n  路径: %s\n", ppid, name, path)
		chain = append(chain, info)
		currentPid = ppid
	}
	return chain
}

func getParentPID(pid uint32) uint32 {
	handle, _, _ := procOpenProcess.Call(PROCESS_QUERY_INFORMATION, 0, uintptr(pid))
	if handle == 0 {
		return 0
	}
	defer procCloseHandle.Call(handle)

	type PROCESS_BASIC_INFORMATION struct {
		Reserved1       uintptr
		PebBaseAddress  uintptr
		Reserved2       [2]uintptr
		UniqueProcessId uintptr
		ParentProcessId uintptr
	}

	var pbi PROCESS_BASIC_INFORMATION
	var returnLength uint32
	ret, _, _ := procNtQueryInformationProcess.Call(
		handle,
		0,
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		uintptr(unsafe.Pointer(&returnLength)),
	)
	if ret != 0 {
		return 0
	}
	return uint32(pbi.ParentProcessId)
}
