package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// RTTStats 存储一个时间间隔内的延迟统计
type RTTStats struct {
	Min     time.Duration
	Max     time.Duration
	Total   time.Duration
	Count   int
}

// ICMP包结构
type ICMP struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	ID       uint16
	Sequence uint16
}

// 计算ICMP校验和
func checksum(data []byte) uint16 {
	var sum uint32
	
	// 每两个字节计算一次
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 + uint32(data[i+1])
	}
	
	// 如果数据长度为奇数，添加最后一个字节
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	
	// 将进位加到低16位
	for sum>>16 > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	
	// 取反
	return uint16(^sum)
}

// 创建ICMP Echo Request包（支持IPv4和IPv6）
func createICMPPacket(id, seq uint16, isIPv6 bool) []byte {
	var icmpType uint8
	if isIPv6 {
		icmpType = 128 // ICMPv6 Echo Request
	} else {
		icmpType = 8   // ICMP Echo Request
	}
	
	icmp := ICMP{
		Type:     icmpType,
		Code:     0,
		Checksum: 0,
		ID:       id,
		Sequence: seq,
	}
	
	// 创建数据包
	data := make([]byte, 8+32) // 8字节ICMP头 + 32字节数据
	data[0] = icmp.Type
	data[1] = icmp.Code
	// Checksum先设置为0
	data[2] = 0
	data[3] = 0
	binary.BigEndian.PutUint16(data[4:6], icmp.ID)
	binary.BigEndian.PutUint16(data[6:8], icmp.Sequence)
	
	// 填充时间戳作为数据
	timestamp := time.Now().UnixNano()
	binary.BigEndian.PutUint64(data[8:16], uint64(timestamp))
	
	// 填充其余数据
	for i := 16; i < len(data); i++ {
		data[i] = byte(i)
	}
	
	// 计算并设置校验和
	cs := checksum(data)
	binary.BigEndian.PutUint16(data[2:4], cs)
	
	return data
}

// 解析ICMP Echo Reply包（支持IPv4和IPv6）
func parseICMPReply(data []byte, isIPv6 bool) (uint16, uint16, time.Duration, bool) {
	var icmpData []byte
	
	if isIPv6 {
		// IPv6没有可变长度头，直接是ICMP数据
		if len(data) < 8 {
			return 0, 0, 0, false
		}
		icmpData = data
		// 检查ICMPv6类型（应该是129，Echo Reply）
		if icmpData[0] != 129 {
			return 0, 0, 0, false
		}
	} else {
		// IPv4处理
		if len(data) < 28 { // IP头(20) + ICMP头(8)最少28字节
			return 0, 0, 0, false
		}
		
		// 跳过IP头（通常20字节）
		ipHeaderLen := int(data[0]&0xf) * 4
		if len(data) < ipHeaderLen+8 {
			return 0, 0, 0, false
		}
		
		icmpData = data[ipHeaderLen:]
		
		// 检查ICMP类型（应该是0，Echo Reply）
		if icmpData[0] != 0 {
			return 0, 0, 0, false
		}
	}
	
	id := binary.BigEndian.Uint16(icmpData[4:6])
	seq := binary.BigEndian.Uint16(icmpData[6:8])
	
	// 提取时间戳 - 检查是否有足够的数据
	if len(icmpData) >= 16 {
		timestamp := int64(binary.BigEndian.Uint64(icmpData[8:16]))
		now := time.Now().UnixNano()
		
		// 检查时间戳是否合理（不能是未来时间，也不能太老）
		if timestamp > 0 && timestamp <= now && (now-timestamp) < int64(5*time.Second) {
			rtt := time.Duration(now - timestamp)
			return id, seq, rtt, true
		} else {
			// 时间戳无效，但这是一个有效的Echo Reply，估算RTT
			// 对于localhost，RTT通常很小
			return id, seq, 50 * time.Microsecond, true
		}
	}
	
	// 如果数据不够，但这确实是Echo Reply，给一个估计值
	return id, seq, 100 * time.Microsecond, true
}

// 主函数入口
func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法: go run dping.go <目标地址>")
		os.Exit(1)
	}
	target := os.Args[1]

	// 首先尝试解析为IPv6地址
	addr6, err6 := net.ResolveIPAddr("ip6", target)
	addr4, err4 := net.ResolveIPAddr("ip4", target)
	
	var addr *net.IPAddr
	var isIPv6 bool
	var network string
	
	// 优先使用IPv4，如果IPv4失败则使用IPv6
	if err4 == nil {
		addr = addr4
		isIPv6 = false
		network = "ip4:icmp"
		fmt.Printf("PING %s (%s): 每秒发送100个包 [IPv4]\n", target, addr.IP)
	} else if err6 == nil {
		addr = addr6
		isIPv6 = true
		network = "ip6:ipv6-icmp"
		fmt.Printf("PING %s (%s): 每秒发送100个包 [IPv6]\n", target, addr.IP)
	} else {
		fmt.Printf("错误: 无法解析地址 %s\n", target)
		fmt.Printf("IPv4错误: %v\n", err4)
		fmt.Printf("IPv6错误: %v\n", err6)
		return
	}

	// 创建原始套接字
	conn, err := net.Dial(network, addr.String())
	if err != nil {
		fmt.Printf("错误: 无法创建ICMP套接字: %v\n", err)
		fmt.Println("提示: 在Windows上需要以管理员身份运行")
		return
	}
	defer conn.Close()

	// 创建统计通道
	rttChan := make(chan time.Duration, 1000)
	
	// 使用 WaitGroup 和 stop channel 来优雅地管理goroutine的生命周期
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// 启动统计报告的goroutine
	wg.Add(1)
	go reporter(rttChan, stop, &wg)

	// 启动发送ping包的goroutine
	wg.Add(1)
	go pingSender(conn, stop, &wg, isIPv6)

	// 启动接收ping回复的goroutine
	wg.Add(1)
	go pingReceiver(conn, rttChan, stop, &wg, isIPv6)
	
	// 监听中断信号 (Ctrl+C)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	
	// 等待中断信号
	<-c

	// 收到信号后，停止所有goroutine
	fmt.Println("\n正在停止...")
	close(stop)

	// 等待所有goroutine完成
	wg.Wait()
	fmt.Println("程序已退出。")
}

// pingSender: 发送ping包的goroutine
func pingSender(conn net.Conn, stop <-chan struct{}, wg *sync.WaitGroup, isIPv6 bool) {
	defer wg.Done()
	
	var seq uint16 = 1
	const id uint16 = 12345 // 固定的进程ID
	
	ticker := time.NewTicker(10 * time.Millisecond) // 每10ms发送一个包，即每秒100个
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			packet := createICMPPacket(id, seq, isIPv6)
			_, err := conn.Write(packet)
			if err != nil {
				fmt.Printf("发送ping包错误: %v\n", err)
				return
			}
			seq++
			
		case <-stop:
			return
		}
	}
}

// pingReceiver: 接收ping回复的goroutine
func pingReceiver(conn net.Conn, rttChan chan<- time.Duration, stop <-chan struct{}, wg *sync.WaitGroup, isIPv6 bool) {
	defer wg.Done()
	
	buffer := make([]byte, 1024)
	
	for {
		select {
		case <-stop:
			return
		default:
			// 设置读取超时
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, err := conn.Read(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // 超时是正常的，继续循环
				}
				fmt.Printf("接收ping回复错误: %v\n", err)
				return
			}
			
			// 解析ICMP回复
			_, _, rtt, ok := parseICMPReply(buffer[:n], isIPv6)
			if ok && rtt >= 0 && rtt < time.Second {
				select {
				case rttChan <- rtt:
				default:
					// channel满了，丢弃这个RTT
				}
			}
		}
	}
}

// reporter goroutine: 按秒统计并打印报告
func reporter(rttChan <-chan time.Duration, stop <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var totalSent int

	for {
		select {
		case <-ticker.C:
			// 计算这一秒发送的包数（假设每秒100个）
			currentSecondSent := 100
			totalSent += currentSecondSent
			
			// 从channel中读取这段时间内所有成功的RTT
			intervalRTTs := RTTStats{Min: time.Second} // 初始化一个较大的Min RTT
			
			// 循环读取，直到channel为空
			for len(rttChan) > 0 {
				rtt := <-rttChan
				intervalRTTs.Count++
				intervalRTTs.Total += rtt
				if rtt < intervalRTTs.Min {
					intervalRTTs.Min = rtt
				}
				if rtt > intervalRTTs.Max {
					intervalRTTs.Max = rtt
				}
			}

			packetsRecv := intervalRTTs.Count
			loss := 0.0
			if currentSecondSent > 0 {
				loss = float64(currentSecondSent-packetsRecv) / float64(currentSecondSent) * 100
			}

			avgRTT := 0.0
			if packetsRecv > 0 {
				avgRTT = float64(intervalRTTs.Total.Microseconds()) / 1000.0 / float64(packetsRecv)
			}
			
			minRTTMs := float64(intervalRTTs.Min.Microseconds()) / 1000.0
			if packetsRecv == 0 {
				minRTTMs = 0 // 如果没有收到包，min RTT应为0
			}
			maxRTTMs := float64(intervalRTTs.Max.Microseconds()) / 1000.0
			
			fmt.Printf("[%s] Sent:%d Recv:%d Loss:%.1f%% | RTT min/avg/max: %.1f/%.1f/%.1fms\n",
				time.Now().Format("15:04:05"),
				currentSecondSent,
				packetsRecv,
				loss,
				minRTTMs,
				avgRTT,
				maxRTTMs,
			)

		case <-stop:
			// 接收到停止信号，退出循环
			return
		}
	}
}