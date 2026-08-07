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
		return
	}
	c.isClosed = true
	_ = c.wsConn.Close()
	c.mu.Unlock()
	c.streams.Range(func(key, value interface{}) bool {
		stream := value.(*MuxStream)
		stream.pipeWriter.Close()
		return true
	})
}

type MuxPool struct {
	serverAddr string
	serverIP   string
	token      string
	client     *MuxClient
	mu         sync.Mutex
}

func NewMuxPool(serverAddr, serverIP, token string) *MuxPool {
	return &MuxPool{
		serverAddr: serverAddr,
		serverIP:   serverIP,
		token:      token,
	}
}

func (p *MuxPool) GetStream(target string) (*MuxStream, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.client != nil {
		stream, err := p.client.OpenStream(target)
		if err == nil {
			return stream, nil
		}
		p.client.Close()
		p.client = nil
	}
	log.Printf("[Mux] 正在建立新的 WebSocket 隧道...")
	wsConn, err := dialWebSocketWithECH(2)
	if err != nil {
		return nil, fmt.Errorf("WebSocket 失败: %w", err)
	}
	p.client = NewMuxClient(wsConn)
	return p.client.OpenStream(target)
}

// ======================== ECH 与 WebSocket ========================

const typeHTTPS = 65

func prepareECH() error {
	echBase64, err := queryHTTPSRecord(echDomain, dnsServer)
	if err != nil {
		return fmt.Errorf("DNS 查询失败: %w", err)
	}
	if echBase64 == "" {
		return errors.New("未找到 ECH 参数")
	}
	raw, err := base64.StdEncoding.DecodeString(echBase64)
	if err != nil {
		return fmt.Errorf("ECH 解码失败: %w", err)
	}
	echListMu.Lock()
	echList = raw
	echListMu.Unlock()
	log.Printf("[ECH] 配置已加载，长度: %d 字节", len(raw))
	return nil
}

func refreshECH() error {
	return prepareECH()
}

func getECHList() ([]byte, error) {
	echListMu.RLock()
	defer echListMu.RUnlock()
	if len(echList) == 0 {
		return nil, errors.New("ECH 配置未加载")
	}
	return echList, nil
}

func buildTLSConfigWithECH(serverName string, echList []byte) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
		RootCAs:    roots,
	}
	if len(echList) > 0 {
		_ = setECHConfig(config, echList)
	}
	return config, nil
}

func setECHConfig(config *tls.Config, echList []byte) error {
	configValue := reflect.ValueOf(config).Elem()
	field1 := configValue.FieldByName("EncryptedClientHelloConfigList")
	if field1.IsValid() && field1.CanSet() {
		field1.Set(reflect.ValueOf(echList))
	}
	field2 := configValue.FieldByName("EncryptedClientHelloRejectionVerify")
	if field2.IsValid() && field2.CanSet() {
		rejectionFunc := func(cs tls.ConnectionState) error {
			return errors.New("服务器拒绝 ECH")
		}
		field2.Set(reflect.ValueOf(rejectionFunc))
	}
	return nil
}

func queryHTTPSRecord(domain, dnsServer string) (string, error) {
	dohURL := dnsServer
	if !strings.HasPrefix(dohURL, "https://") && !strings.HasPrefix(dohURL, "http://") {
		dohURL = "https://" + dohURL
	}
	return queryDoH(domain, dohURL)
}

func queryDoH(domain, dohURL string) (string, error) {
	u, err := url.Parse(dohURL)
	if err != nil {
		return "", err
	}
	dnsQuery := buildDNSQuery(domain, typeHTTPS)
	dnsBase64 := base64.RawURLEncoding.EncodeToString(dnsQuery)
	q := u.Query()
	q.Set("dns", dnsBase64)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return parseDNSResponse(body)
}

func buildDNSQuery(domain string, qtype uint16) []byte {
	query := make([]byte, 0, 512)
	query = append(query, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, label := range strings.Split(domain, ".") {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00, byte(qtype>>8), byte(qtype), 0x00, 0x01)
	return query
}

func parseDNSResponse(response []byte) (string, error) {
	if len(response) < 12 {
		return "", errors.New("响应过短")
	}
	ancount := binary.BigEndian.Uint16(response[6:8])
	if ancount == 0 {
		return "", errors.New("无应答记录")
	}
	offset := 12
	for offset < len(response) && response[offset] != 0 {
		offset += int(response[offset]) + 1
	}
	offset += 5
	for i := 0; i < int(ancount); i++ {
		if offset >= len(response) {
			break
		}
		if response[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(response) && response[offset] != 0 {
				offset += int(response[offset]) + 1
			}
			offset++
		}
		if offset+10 > len(response) {
			break
		}
		rrType := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 8
		dataLen := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2
		if offset+int(dataLen) > len(response) {
			break
		}
		data := response[offset : offset+int(dataLen)]
		offset += int(dataLen)
		if rrType == typeHTTPS {
			if ech := parseHTTPSRecord(data); ech != "" {
				return ech, nil
			}
		}
	}
	return "", nil
}

func parseHTTPSRecord(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	offset := 2
	if offset < len(data) && data[offset] == 0 {
		offset++
	} else {
		for offset < len(data) && data[offset] != 0 {
			offset += int(data[offset]) + 1
		}
		offset++
	}
	for offset+4 <= len(data) {
		key := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		if offset+int(length) > len(data) {
			break
		}
		value := data[offset : offset+int(length)]
		offset += int(length)
		if key == 5 {
			return base64.StdEncoding.EncodeToString(value)
		}
	}
	return ""
}

func parseServerAddr(addr string) (host, port, path string, err error) {
	path = "/"
	slashIdx := strings.Index(addr, "/")
	if slashIdx != -1 {
		path = addr[slashIdx:]
		addr = addr[:slashIdx]
	}
	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		return "", "", "", err
	}
	return host, port, path, nil
}

func dialWebSocketWithECH(maxRetries int) (*websocket.Conn, error) {
	host, port, path, err := parseServerAddr(serverAddr)
	if err != nil {
		return nil, err
	}
	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path)

	for attempt := 1; attempt <= maxRetries; attempt++ {
		echBytes, echErr := getECHList()
		if echErr != nil {
			if attempt < maxRetries {
				refreshECH()
				continue
			}
			return nil, echErr
		}
		tlsCfg, tlsErr := buildTLSConfigWithECH(host, echBytes)
		if tlsErr != nil {
			return nil, tlsErr
		}
		dialer := websocket.Dialer{
			TLSClientConfig: tlsCfg,
			Subprotocols: func() []string {
				if token == "" {
					return nil
				}
				return []string{token}
			}(),
			HandshakeTimeout: 10 * time.Second,
		}
		if serverIP != "" {
			dialer.NetDial = func(network, address string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				return net.DialTimeout(network, net.JoinHostPort(serverIP, port), 10*time.Second)
			}
		}
		wsConn, _, dialErr := dialer.Dial(wsURL, nil)
		if dialErr != nil {
			if strings.Contains(dialErr.Error(), "ECH") && attempt < maxRetries {
				refreshECH()
				time.Sleep(time.Second)
				continue
			}
			return nil, dialErr
		}
		return wsConn, nil
	}
	return nil, errors.New("已达最大重试次数")
}

func queryDoHForProxy(dnsQuery []byte) ([]byte, error) {
	_, port, _, err := parseServerAddr(serverAddr)
	if err != nil {
		return nil, err
	}
	dohURL := fmt.Sprintf("https://cloudflare-dns.com:%s/dns-query", port)
	echBytes, err := getECHList()
	if err != nil {
		return nil, err
	}
	tlsCfg, err := buildTLSConfigWithECH("cloudflare-dns.com", echBytes)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
	}
	if serverIP != "" {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, net.JoinHostPort(serverIP, port))
		}
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	req, err := http.NewRequest("POST", dohURL, bytes.NewReader(dnsQuery))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH error: %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// ======================== 统一代理服务器 ========================

const (
	modeSOCKS5      = 1
	modeHTTPConnect = 2
	modeHTTPProxy   = 3
)

func runProxyServer(addr string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("[代理] 监听失败: %v", err)
	}
	defer listener.Close()

	log.Printf("[代理] 服务器启动: %s (支持 SOCKS5 和 HTTP)", addr)
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	clientAddr := conn.RemoteAddr().String()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}
	firstByte := buf[0]
	switch firstByte {
	case 0x05:
		handleSOCKS5(conn, clientAddr, firstByte)
	case 'C', 'G', 'P', 'H', 'D', 'O', 'T':
		handleHTTP(conn, clientAddr, firstByte)
	}
}

func handleSOCKS5(conn net.Conn, clientAddr string, firstByte byte) {
	if firstByte != 0x05 {
		return
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	methods := make([]byte, buf[0])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	buf = make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	if buf[0] != 5 {
		return
	}
	command, atyp := buf[1], buf[3]
	var host string
	switch atyp {
	case 0x01:
		buf = make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		host = net.IP(buf).String()
	case 0x03:
		buf = make([]byte, 1)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		domainBuf := make([]byte, buf[0])
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return
		}
		host = string(domainBuf)
	case 0x04:
		buf = make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		host = net.IP(buf).String()
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	buf = make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	port := int(buf[0])<<8 | int(buf[1])

	switch command {
	case 0x01: // CONNECT
		target := fmt.Sprintf("%s:%d", host, port)
		if atyp == 0x04 {
			target = fmt.Sprintf("[%s]:%d", host, port)
		}
		_ = handleTunnel(conn, target, clientAddr, modeSOCKS5, "")
	case 0x03: // UDP ASSOCIATE
		handleUDPAssociate(conn, clientAddr)
	default:
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
}

func handleUDPAssociate(tcpConn net.Conn, clientAddr string) {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		tcpConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		tcpConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	port := udpConn.LocalAddr().(*net.UDPAddr).Port
	response := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, byte(port >> 8), byte(port & 0xff)}
	if _, err := tcpConn.Write(response); err != nil {
		udpConn.Close()
		return
	}
	stopChan := make(chan struct{})
	go handleUDPRelay(udpConn, clientAddr, stopChan)
	buf := make([]byte, 1)
	tcpConn.Read(buf)
	close(stopChan)
	udpConn.Close()
}

func handleUDPRelay(udpConn *net.UDPConn, clientAddr string, stopChan chan struct{}) {
	buf := make([]byte, 65535)
	for {
		select {
		case <-stopChan:
			return
		default:
		}
		udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if n < 10 {
			continue
		}
		data := buf[:n]
		if data[2] != 0x00 {
			continue
		}
		atyp := data[3]
		var headerLen int
		var dstPort int
		switch atyp {
		case 0x01:
			if n < 10 {
				continue
			}
			dstPort = int(data[8])<<8 | int(data[9])
			headerLen = 10
		case 0x03:
			if n < 5 {
				continue
			}
			domainLen := int(data[4])
			if n < 7+domainLen {
				continue
			}
			dstPort = int(data[5+domainLen])<<8 | int(data[6+domainLen])
			headerLen = 7 + domainLen
		case 0x04:
			if n < 22 {
				continue
			}
			dstPort = int(data[20])<<8 | int(data[21])
			headerLen = 22
		default:
			continue
		}
		if dstPort == 53 {
			go handleDNSQuery(udpConn, addr, data[headerLen:], data[:headerLen])
		}
	}
}

func handleDNSQuery(udpConn *net.UDPConn, clientAddr *net.UDPAddr, dnsQuery []byte, socks5Header []byte) {
	dnsResponse, err := queryDoHForProxy(dnsQuery)
	if err != nil {
		return
	}
	response := append(socks5Header, dnsResponse...)
	udpConn.WriteToUDP(response, clientAddr)
}

func handleHTTP(conn net.Conn, clientAddr string, firstByte byte) {
	reader := bufio.NewReader(io.MultiReader(strings.NewReader(string(firstByte)), conn))
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Fields(requestLine)
	if len(parts) < 3 {
		return
	}
	method, requestURL, httpVersion := parts[0], parts[1], parts[2]
	headers := make(map[string]string)
	var headerLines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		headerLines = append(headerLines, line)
		if idx := strings.Index(line, ":"); idx > 0 {
			headers[strings.ToLower(strings.TrimSpace(line[:idx]))] = strings.TrimSpace(line[idx+1:])
		}
	}

	if method == "CONNECT" {
		_ = handleTunnel(conn, requestURL, clientAddr, modeHTTPConnect, "")
	} else {
		var target, path string
		if strings.HasPrefix(requestURL, "http://") {
			urlWithoutScheme := strings.TrimPrefix(requestURL, "http://")
			idx := strings.Index(urlWithoutScheme, "/")
			if idx > 0 {
				target, path = urlWithoutScheme[:idx], urlWithoutScheme[idx:]
			} else {
				target, path = urlWithoutScheme, "/"
			}
		} else {
			target, path = headers["host"], requestURL
		}
		if target == "" {
			conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return
		}
		if !strings.Contains(target, ":") {
			target += ":80"
		}

		var reqBuilder strings.Builder
		reqBuilder.WriteString(fmt.Sprintf("%s %s %s\r\n", method, path, httpVersion))
		for _, line := range headerLines {
			k := strings.ToLower(strings.TrimSpace(strings.Split(line, ":")[0]))
			if k != "proxy-connection" && k != "proxy-authorization" {
				reqBuilder.WriteString(line + "\r\n")
			}
		}
		reqBuilder.WriteString("\r\n")
		if cl := headers["content-length"]; cl != "" {
			var length int
			fmt.Sscanf(cl, "%d", &length)
			if length > 0 && length < 10*1024*1024 {
				body := make([]byte, length)
				if _, err := io.ReadFull(reader, body); err == nil {
					reqBuilder.Write(body)
				}
			}
		}
		_ = handleTunnel(conn, target, clientAddr, modeHTTPProxy, reqBuilder.String())
	}
}

func handleTunnel(conn net.Conn, target, clientAddr string, mode int, firstFrame string) error {
	targetHost, _, err := net.SplitHostPort(target)
	if err != nil {
		targetHost = target
	}

	// 执行分流判断
	if shouldBypassProxy(targetHost) {
		log.Printf("[分流] %s -> %s (直连)", clientAddr, target)
		return handleDirectConnection(conn, target, mode, firstFrame)
	}

	log.Printf("[分流] %s -> %s (通过代理 Mux)", clientAddr, target)

	// 使用全局 Mux 复用池获取流
	stream, err := globalMuxPool.GetStream(target)
	if err != nil {
		sendErrorResponse(conn, mode)
		return err
	}
	defer stream.Close()

	conn.SetDeadline(time.Time{})

	// 针对纯 SOCKS5 连接，如果没有提供首帧数据，则主动探测一下（避免部分软件卡死）
	if firstFrame == "" && mode == modeSOCKS5 {
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		buffer := make([]byte, 32768)
		n, _ := conn.Read(buffer)
		_ = conn.SetReadDeadline(time.Time{})
		if n > 0 {
			firstFrame = string(buffer[:n])
		}
	}

	// 代理端回复连接成功
	if err := sendSuccessResponse(conn, mode); err != nil {
		return err
	}

	// 如果有数据包，发送出去
	if firstFrame != "" {
		if _, err := stream.Write([]byte(firstFrame)); err != nil {
			return err
		}
	}

	log.Printf("[代理] %s 已连接: %s", clientAddr, target)

	done := make(chan bool, 2)
	go func() {
		io.Copy(stream, conn)
		done <- true
	}()
	go func() {
		io.Copy(conn, stream)
		done <- true
	}()
	<-done
	log.Printf("[代理] %s 已断开: %s", clientAddr, target)
	return nil
}

func handleDirectConnection(conn net.Conn, target string, mode int, firstFrame string) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		if mode == modeHTTPConnect || mode == modeHTTPProxy {
			port = "443"
		} else {
			port = "80"
		}
		target = net.JoinHostPort(host, port)
	}
	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		sendErrorResponse(conn, mode)
		return err
	}
	defer targetConn.Close()

	if err := sendSuccessResponse(conn, mode); err != nil {
		return err
	}
	if firstFrame != "" {
		targetConn.Write([]byte(firstFrame))
	}
	done := make(chan bool, 2)
	go func() {
		io.Copy(targetConn, conn)
		done <- true
	}()
	go func() {
		io.Copy(conn, targetConn)
		done <- true
	}()
	<-done
	return nil
}

func sendErrorResponse(conn net.Conn, mode int) {
	switch mode {
	case modeSOCKS5:
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	case modeHTTPConnect, modeHTTPProxy:
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
	}
}

func sendSuccessResponse(conn net.Conn, mode int) error {
	switch mode {
	case modeSOCKS5:
		_, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return err
	case modeHTTPConnect:
		_, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		return err
	}
	return nil
}
