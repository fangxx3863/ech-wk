package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
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
	listenAddr string
	serverAddr string
	serverIP   string
	token      string
	dnsServer  string
	echDomain  string

	echListMu sync.RWMutex
	echList   []byte

	globalMuxPool *MuxPool
)

func init() {
	flag.StringVar(&listenAddr, "l", "127.0.0.1:30000", "本地 SOCKS5 代理监听地址")
	flag.StringVar(&serverAddr, "f", "", "服务端地址 (格式: x.x.workers.dev:443)")
	flag.StringVar(&serverIP, "ip", "", "指定服务端 IP (优选 IP，绕过 DNS 解析)")
	flag.StringVar(&token, "token", "", "身份验证令牌 (可选)")
	flag.StringVar(&dnsServer, "dns", "dns.alidns.com/dns-query", "ECH 查询 DoH 服务器")
	flag.StringVar(&echDomain, "ech", "cloudflare-ech.com", "ECH 查询域名")
}

func main() {
	flag.Parse()

	if serverAddr == "" {
		log.Fatal("必须指定服务端地址 -f\n\n示例:\n  ./client -l 127.0.0.1:30000 -f your-worker.workers.dev:443 -ip 104.16.x.x")
	}

	log.Printf("[启动] 正在获取 ECH 配置...")
	if err := prepareECH(); err != nil {
		log.Printf("[警告] 获取 ECH 配置失败 (将不使用 ECH 直连): %v", err)
	}

	// 初始化 Mux 连接池
	globalMuxPool = NewMuxPool(serverAddr, serverIP, token)

	// 启动 SOCKS5 代理服务器
	runSocks5Server(listenAddr)
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
	streams   sync.Map // streamId (uint32) -> *MuxStream
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

	// 发送 CMD_OPEN 帧
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

// MuxPool 动态管理 Mux 长连接
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

	log.Printf("[Mux] 正在建立新的复用 WebSocket 长连接...")
	wsConn, err := dialWebSocketWithECH(2)
	if err != nil {
		return nil, fmt.Errorf("建立 WebSocket 失败: %w", err)
	}

	p.client = NewMuxClient(wsConn)
	return p.client.OpenStream(target)
}

// ======================== SOCKS5 服务端 ========================

func runSocks5Server(addr string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("[SOCKS5] 监听失败: %v", err)
	}
	defer listener.Close()

	log.Printf("[SOCKS5] 代理已启动，监听于: %s", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleSocks5Conn(conn)
	}
}

func handleSocks5Conn(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 256)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil || buf[0] != 0x05 {
		return
	}

	numMethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:numMethods]); err != nil {
		return
	}

	// 响应无认证模式
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 读取请求
	if _, err := io.ReadFull(conn, buf[:4]); err != nil || buf[1] != 0x01 { // CMD != CONNECT
		return
	}

	var host string
	switch buf[3] { // ATYP
	case 0x01: // IPv4
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
	case 0x03: // Domain
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		domainLen := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:domainLen]); err != nil {
			return
		}
		host = string(buf[:domainLen])
	case 0x04: // IPv6
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
	default:
		return
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(buf[:2])
	target := fmt.Sprintf("%s:%d", host, port)

	// 打开 Mux 复用流
	stream, err := globalMuxPool.GetStream(target)
	if err != nil {
		log.Printf("[SOCKS5] 连接目标失败 %s: %v", target, err)
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer stream.Close()

	// 响应 SOCKS5 建立成功
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// 双向数据转发
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(stream, conn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, stream)
		done <- struct{}{}
	}()

	<-done
}

// ======================== WebSocket 与 ECH 底层支持 ========================

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
		echBytes, _ := getECHList()

		tlsCfg, _ := buildTLSConfigWithECH(host, echBytes)

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
		if dialErr == nil {
			return wsConn, nil
		}
		time.Sleep(time.Second)
	}

	return nil, fmt.Errorf("连接失败，达到最大尝试次数")
}

func prepareECH() error {
	echBase64, err := queryDoH(echDomain, dnsServer)
	if err != nil || echBase64 == "" {
		return fmt.Errorf("未找到 ECH 参数")
	}
	raw, err := base64.StdEncoding.DecodeString(echBase64)
	if err != nil {
		return err
	}
	echListMu.Lock()
	echList = raw
	echListMu.Unlock()
	return nil
}

func getECHList() ([]byte, error) {
	echListMu.RLock()
	defer echListMu.RUnlock()
	return echList, nil
}

func buildTLSConfigWithECH(serverName string, echList []byte) (*tls.Config, error) {
	roots, _ := x509.SystemCertPool()
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
	return nil
}

func queryDoH(domain, dohURL string) (string, error) {
	if !strings.HasPrefix(dohURL, "https://") && !strings.HasPrefix(dohURL, "http://") {
		dohURL = "https://" + dohURL
	}
	u, err := url.Parse(dohURL)
	if err != nil {
		return "", err
	}

	dnsQuery := buildDNSQuery(domain, 65) // HTTPS 记录
	q := u.Query()
	q.Set("dns", base64.RawURLEncoding.EncodeToString(dnsQuery))
	u.RawQuery = q.Encode()

	req, _ := http.NewRequest("GET", u.String(), nil)
	req.Header.Set("Accept", "application/dns-message")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
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
		return "", fmt.Errorf("short response")
	}
	ancount := binary.BigEndian.Uint16(response[6:8])
	if ancount == 0 {
		return "", fmt.Errorf("no answer")
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

		if rrType == 65 { // HTTPS 记录
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
		if key == 5 { // ECH 秘钥 KeyID = 5
			return base64.StdEncoding.EncodeToString(value)
		}
	}
	return ""
}
