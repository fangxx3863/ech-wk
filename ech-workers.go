package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// ======================== Mux 协议常量 ========================

const (
	CMD_OPEN  byte = 0x01
	CMD_DATA  byte = 0x02
	CMD_CLOSE byte = 0x03
)

// ======================== 全局参数 ========================

var (
	listenAddr  string
	serverAddr  string
	serverIP    string
	token       string
	dnsServer   string
	echDomain   string
	routingMode string // 分流模式: "global", "bypass_cn", "none"

	echListMu sync.RWMutex
	echList   []byte

	// 中国IP列表（IPv4）
	chinaIPRangesMu sync.RWMutex
	chinaIPRanges   []ipRange

	// 中国IP列表（IPv6）
	chinaIPV6RangesMu sync.RWMutex
	chinaIPV6Ranges   []ipRangeV6

	globalMuxPool *MuxPool
)

// ipRange 表示一个IPv4 IP范围
type ipRange struct {
	start uint32
	end   uint32
}

// ipRangeV6 表示一个IPv6 IP范围
type ipRangeV6 struct {
	start [16]byte
	end   [16]byte
}

func init() {
	flag.StringVar(&listenAddr, "l", "127.0.0.1:30000", "代理监听地址 (支持 SOCKS5 和 HTTP)")
	flag.StringVar(&serverAddr, "f", "", "服务端地址 (格式: x.x.workers.dev:443)")
	flag.StringVar(&serverIP, "ip", "", "指定服务端 IP（绕过 DNS 解析）")
	flag.StringVar(&token, "token", "", "身份验证令牌")
	flag.StringVar(&dnsServer, "dns", "dns.alidns.com/dns-query", "ECH 查询 DoH 服务器")
	flag.StringVar(&echDomain, "ech", "cloudflare-ech.com", "ECH 查询域名")
	flag.StringVar(&routingMode, "routing", "global", "分流模式: global(全局代理), bypass_cn(跳过中国大陆), none(不改变代理)")
}

func main() {
	flag.Parse()

	if serverAddr == "" {
		log.Fatal("必须指定服务端地址 -f\n\n示例:\n  ./client -l 127.0.0.1:1080 -f your-worker.workers.dev:443 -token your-token")
	}

	log.Printf("[启动] 正在获取 ECH 配置...")
	if err := prepareECH(); err != nil {
		log.Fatalf("[启动] 获取 ECH 配置失败: %v", err)
	}

	// 加载中国IP列表（如果需要）
	if routingMode == "bypass_cn" {
		log.Printf("[启动] 分流模式: 跳过中国大陆，正在加载中国IP列表...")
		ipv4Count := 0
		ipv6Count := 0

		if err := loadChinaIPList(); err != nil {
			log.Printf("[警告] 加载中国IPv4列表失败: %v", err)
		} else {
			chinaIPRangesMu.RLock()
			ipv4Count = len(chinaIPRanges)
			chinaIPRangesMu.RUnlock()
		}

		if err := loadChinaIPV6List(); err != nil {
			log.Printf("[警告] 加载中国IPv6列表失败: %v", err)
		} else {
			chinaIPV6RangesMu.RLock()
			ipv6Count = len(chinaIPV6Ranges)
			chinaIPV6RangesMu.RUnlock()
		}

		if ipv4Count > 0 || ipv6Count > 0 {
			log.Printf("[启动] 已加载 %d 个中国IPv4段, %d 个中国IPv6段", ipv4Count, ipv6Count)
		} else {
			log.Printf("[警告] 未加载到任何中国IP列表，将使用默认规则")
		}
	} else if routingMode == "global" {
		log.Printf("[启动] 分流模式: 全局代理")
	} else if routingMode == "none" {
		log.Printf("[启动] 分流模式: 不改变代理（直连模式）")
	} else {
		log.Printf("[警告] 未知的分流模式: %s，使用默认模式 global", routingMode)
		routingMode = "global"
	}

	// 初始化 Mux 复用连接池
	globalMuxPool = NewMuxPool(serverAddr, serverIP, token)

	runProxyServer(listenAddr)
}

// ======================== 工具函数 ========================

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func isChinaIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	if ip.To4() != nil {
		ipUint32 := ipToUint32(ip)
		if ipUint32 == 0 {
			return false
		}
		chinaIPRangesMu.RLock()
		defer chinaIPRangesMu.RUnlock()
		left, right := 0, len(chinaIPRanges)
		for left < right {
			mid := (left + right) / 2
			r := chinaIPRanges[mid]
			if ipUint32 < r.start {
				right = mid
			} else if ipUint32 > r.end {
				left = mid + 1
			} else {
				return true
			}
		}
		return false
	}

	ipBytes := ip.To16()
	if ipBytes == nil {
		return false
	}
	var ipArray [16]byte
	copy(ipArray[:], ipBytes)

	chinaIPV6RangesMu.RLock()
	defer chinaIPV6RangesMu.RUnlock()
	left, right := 0, len(chinaIPV6Ranges)
	for left < right {
		mid := (left + right) / 2
		r := chinaIPV6Ranges[mid]
		cmpStart := compareIPv6(ipArray, r.start)
		if cmpStart < 0 {
			right = mid
			continue
		}
		cmpEnd := compareIPv6(ipArray, r.end)
		if cmpEnd > 0 {
			left = mid + 1
			continue
		}
		return true
	}
	return false
}

func compareIPv6(a, b [16]byte) int {
	for i := 0; i < 16; i++ {
		if a[i] < b[i] {
			return -1
		} else if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func downloadIPList(url, filePath string) error {
	log.Printf("[下载] 正在下载 IP 列表: %s", url)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("下载失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败: HTTP %d", resp.StatusCode)
	}
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取下载内容失败: %w", err)
	}
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		return fmt.Errorf("保存文件失败: %w", err)
	}
	return nil
}

func loadChinaIPList() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	ipListFile := filepath.Join(filepath.Dir(exePath), "chn_ip.txt")
	if _, err := os.Stat(ipListFile); os.IsNotExist(err) {
		ipListFile = "chn_ip.txt"
	}

	needDownload := false
	if info, err := os.Stat(ipListFile); os.IsNotExist(err) || info.Size() == 0 {
		needDownload = true
	}

	if needDownload {
		url := "https://raw.githubusercontent.com/mayaxcn/china-ip-list/refs/heads/master/chn_ip.txt"
		if err := downloadIPList(url, ipListFile); err != nil {
			return err
		}
	}

	file, err := os.Open(ipListFile)
	if err != nil {
		return err
	}
	defer file.Close()

	var ranges []ipRange
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		startIP, endIP := net.ParseIP(parts[0]), net.ParseIP(parts[1])
		if startIP == nil || endIP == nil {
			continue
		}
		start, end := ipToUint32(startIP), ipToUint32(endIP)
		if start > 0 && end > 0 && start <= end {
			ranges = append(ranges, ipRange{start: start, end: end})
		}
	}
	if len(ranges) == 0 {
		return errors.New("IP列表为空")
	}

	for i := 0; i < len(ranges)-1; i++ {
		for j := i + 1; j < len(ranges); j++ {
			if ranges[i].start > ranges[j].start {
				ranges[i], ranges[j] = ranges[j], ranges[i]
			}
		}
	}

	chinaIPRangesMu.Lock()
	chinaIPRanges = ranges
	chinaIPRangesMu.Unlock()
	return nil
}

func loadChinaIPV6List() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	ipListFile := filepath.Join(filepath.Dir(exePath), "chn_ip_v6.txt")
	if _, err := os.Stat(ipListFile); os.IsNotExist(err) {
		ipListFile = "chn_ip_v6.txt"
	}

	needDownload := false
	if info, err := os.Stat(ipListFile); os.IsNotExist(err) || info.Size() == 0 {
		needDownload = true
	}

	if needDownload {
		url := "https://raw.githubusercontent.com/mayaxcn/china-ip-list/refs/heads/master/chn_ip_v6.txt"
		if err := downloadIPList(url, ipListFile); err != nil {
			return nil
		}
	}

	file, err := os.Open(ipListFile)
	if err != nil {
		return nil
	}
	defer file.Close()

	var ranges []ipRangeV6
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		startIP, endIP := net.ParseIP(parts[0]), net.ParseIP(parts[1])
		if startIP == nil || endIP == nil {
			continue
		}
		startBytes, endBytes := startIP.To16(), endIP.To16()
		if startBytes == nil || endBytes == nil {
			continue
		}
		var start, end [16]byte
		copy(start[:], startBytes)
		copy(end[:], endBytes)
		if compareIPv6(start, end) <= 0 {
			ranges = append(ranges, ipRangeV6{start: start, end: end})
		}
	}
	if len(ranges) == 0 {
		return nil
	}

	for i := 0; i < len(ranges)-1; i++ {
		for j := i + 1; j < len(ranges); j++ {
			if compareIPv6(ranges[i].start, ranges[j].start) > 0 {
				ranges[i], ranges[j] = ranges[j], ranges[i]
			}
		}
	}
	chinaIPV6RangesMu.Lock()
	chinaIPV6Ranges = ranges
	chinaIPV6RangesMu.Unlock()
	return nil
}

func shouldBypassProxy(targetHost string) bool {
	if routingMode == "none" {
		return true
	}
	if routingMode == "global" {
		return false
	}
	if routingMode == "bypass_cn" {
		if ip := net.ParseIP(targetHost); ip != nil {
			return isChinaIP(targetHost)
		}
		ips, err := net.LookupIP(targetHost)
		if err != nil {
			return false
		}
		for _, ip := range ips {
			if isChinaIP(ip.String()) {
				return true
			}
		}
		return false
	}
	return false
}

func isNormalCloseError(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "normal closure")
}

// ======================== Mux 核心多路复用引擎 ========================

type MuxStream struct {
	id         uint32
	client     *MuxClient
	pipeReader *io.PipeReader
	pipeWriter *io.PipeWriter
	closeOnce  sync.Once
}

func NewMuxStream(id uint32, client *MuxClient) *MuxStream {
	pr, pw := io.Pipe()
	return &MuxStream{
		id:         id,
		client:     client,
		pipeReader: pr,
		pipeWriter: pw,
	}
}

func (s *MuxStream) Read(b []byte) (int, error) {
	return s.pipeReader.Read(b)
}

func (s *MuxStream) Write(b []byte) (int, error) {
	err := s.client.SendFrame(CMD_DATA, s.id, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (s *MuxStream) Close() error {
	s.closeOnce.Do(func() {
		_ = s.client.SendFrame(CMD_CLOSE, s.id, nil)
		s.pipeWriter.Close()
		s.pipeReader.Close()
		s.client.removeStream(s.id)
	})
	return nil
}

type MuxClient struct {
	wsConn    *websocket.Conn
	mu        sync.Mutex
	streams   sync.Map
	streamSeq uint32
	isClosed  bool
}

func NewMuxClient(ws *websocket.Conn) *MuxClient {
	c := &MuxClient{
		wsConn: ws,
	}
	go c.readLoop()
	go c.pingLoop()
	return c
}

func (c *MuxClient) OpenStream(target string) (*MuxStream, error) {
	c.mu.Lock()
	if c.isClosed {
		c.mu.Unlock()
		return nil, fmt.Errorf("websocket 已关闭")
	}
	streamID := atomic.AddUint32(&c.streamSeq, 1)
	stream := NewMuxStream(streamID, c)
	c.streams.Store(streamID, stream)
	c.mu.Unlock()

	err := c.SendFrame(CMD_OPEN, streamID, []byte(target))
	if err != nil {
		stream.Close()
		return nil, err
	}
	return stream, nil
}

func (c *MuxClient) removeStream(id uint32) {
	c.streams.Delete(id)
}

func (c *MuxClient) SendFrame(cmd byte, streamID uint32, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.isClosed {
		return fmt.Errorf("connection closed")
	}
	frameLen := 5 + len(payload)
	buf := make([]byte, frameLen)
	buf[0] = cmd
	binary.BigEndian.PutUint32(buf[1:5], streamID)
	if len(payload) > 0 {
		copy(buf[5:], payload)
	}
	return c.wsConn.WriteMessage(websocket.BinaryMessage, buf)
}

func (c *MuxClient) readLoop() {
	defer c.Close()
	for {
		messageType, data, err := c.wsConn.ReadMessage()
		if err != nil {
			break
		}
		if messageType != websocket.BinaryMessage || len(data) < 5 {
			continue
		}
		cmd := data[0]
		streamID := binary.BigEndian.Uint32(data[1:5])
		payload := data[5:]
		val, ok := c.streams.Load(streamID)
		if !ok {
			continue
		}
		stream := val.(*MuxStream)
		switch cmd {
		case CMD_DATA:
			if len(payload) > 0 {
				_, _ = stream.pipeWriter.Write(payload)
			}
		case CMD_CLOSE:
			stream.pipeWriter.Close()
			c.streams.Delete(streamID)
		}
	}
}

func (c *MuxClient) pingLoop() {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		c.mu.Lock()
		if c.isClosed {
			c.mu.Unlock()
			return
		}
		_ = c.wsConn.WriteMessage(websocket.PingMessage, nil)
		c.mu.Unlock()
	}
}

func (c *MuxClient) Close() {
	c.mu.Lock()
	if c.isClosed {
		c.mu.Unlock()
		r
