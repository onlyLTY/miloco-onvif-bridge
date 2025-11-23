package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"miloco_onvif_bridge/internal/onvif"
	"miloco_onvif_bridge/internal/rtsp"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bluenviron/gortsplib/v5"
	"github.com/joho/godotenv"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

var log = logrus.New()

func init() {
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	log.SetLevel(logrus.InfoLevel)
}

// RTSPBridge 结构体
type RTSPBridge struct {
	baseURL            string
	username           string
	password           string
	cameraID           string
	channel            string
	videoCodec         string
	rtspPort           string
	httpClient         *http.Client
	process            *exec.Cmd
	stdin              io.WriteCloser
	waitingForKeyframe bool
	mu                 sync.Mutex
	ctx                context.Context
	cancel             context.CancelFunc
}

// NewRTSPBridge 创建新的 RTSP 桥接实例
func NewRTSPBridge(baseURL, username, password, cameraID, channel, videoCodec, rtspPort string) *RTSPBridge {
	jar, _ := cookiejar.New(nil)

	// 创建 HTTP 客户端,跳过 SSL 验证
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: tr,
		Jar:       jar,
		Timeout:   30 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &RTSPBridge{
		baseURL:            baseURL,
		username:           username,
		password:           password,
		cameraID:           cameraID,
		channel:            channel,
		videoCodec:         videoCodec,
		rtspPort:           rtspPort,
		httpClient:         client,
		waitingForKeyframe: true,
		ctx:                ctx,
		cancel:             cancel,
	}
}

// Login 登录并获取访问令牌
func (r *RTSPBridge) Login() error {
	loginURL := fmt.Sprintf("%s/api/auth/login", r.baseURL)

	payload := map[string]string{
		"username": r.username,
		"password": r.password,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal login payload: %w", err)
	}

	resp, err := r.httpClient.Post(loginURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("login request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login failed: %d - %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode login response: %w", err)
	}

	log.Infof("Login successful: %v", result)

	// 检查登录状态
	statusURL := fmt.Sprintf("%s/api/miot/login_status", r.baseURL)
	statusResp, err := r.httpClient.Get(statusURL)
	if err != nil {
		return fmt.Errorf("login status check: %w", err)
	}
	defer statusResp.Body.Close()

	if statusResp.StatusCode != http.StatusOK {
		return fmt.Errorf("login status check failed: %d", statusResp.StatusCode)
	}

	return nil
}

// StartFFMpeg 启动 FFMpeg 作为 RTSP 服务端
func (r *RTSPBridge) StartFFMpeg() error {
	// FFMpeg 命令:作为 RTSP 服务端监听端口
	args := []string{
		"-y",
		"-v", "error",
		"-hide_banner",
		"-use_wallclock_as_timestamps", "1",
		"-analyzeduration", "20000000",
		"-probesize", "20000000",
		"-f", r.videoCodec,
		"-i", "pipe:0",
		"-c:v", "copy",
		"-c:a", "copy",
		"-f", "rtsp",
		"-rtsp_transport", "tcp",
		fmt.Sprintf("rtsp://127.0.0.1:%s/live", r.rtspPort),
	}

	r.process = exec.CommandContext(r.ctx, "ffmpeg", args...)

	stdin, err := r.process.StdinPipe()
	if err != nil {
		return fmt.Errorf("create stdin pipe: %w", err)
	}
	r.stdin = stdin

	// 捕获 stderr 用于调试
	stderr, err := r.process.StderrPipe()
	if err != nil {
		return fmt.Errorf("create stderr pipe: %w", err)
	}

	if err := r.process.Start(); err != nil {
		return fmt.Errorf("start ffmpeg: %w", err)
	}

	// 启动协程实时读取 stderr
	go func() {
		scanner := io.Reader(stderr)
		buf := make([]byte, 1024)
		for {
			n, err := scanner.Read(buf)
			if n > 0 {
				log.Warnf("FFMpeg: %s", string(buf[:n]))
			}
			if err != nil {
				if err != io.EOF {
					log.Errorf("Error reading FFMpeg stderr: %v", err)
				}
				break
			}
		}
	}()

	// 监控 FFMpeg 进程状态
	go func() {
		err := r.process.Wait()
		if err != nil {
			log.Errorf("FFMpeg process exited with error: %v", err)
		} else {
			log.Warn("FFMpeg process exited normally")
		}
		r.mu.Lock()
		r.stdin = nil
		r.process = nil
		r.mu.Unlock()
	}()

	// 等待 FFMpeg 启动
	time.Sleep(2 * time.Second)

	log.Infof("FFMpeg启动。RTSP stream 已可用 rtsp://<your-ip>:%s/live", r.rtspPort)
	return nil
}

// StopFFMpeg 停止 FFMpeg 进程
func (r *RTSPBridge) StopFFMpeg() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.stdin != nil {
		r.stdin.Close()
		r.stdin = nil
	}

	if r.process != nil && r.process.Process != nil {
		r.process.Process.Signal(syscall.SIGTERM)

		// 等待进程结束,超时后强制杀死
		done := make(chan error, 1)
		go func() {
			done <- r.process.Wait()
		}()

		select {
		case <-done:
			log.Info("FFMpeg process terminated gracefully")
		case <-time.After(5 * time.Second):
			log.Warn("FFMpeg process did not terminate, killing...")
			r.process.Process.Kill()
		}

		r.process = nil
	}
}

// IsKeyframe 检测是否为关键帧
func (r *RTSPBridge) IsKeyframe(data []byte) bool {
	if r.videoCodec == "h264" {
		return r.isH264Keyframe(data)
	} else if r.videoCodec == "hevc" {
		return r.isHEVCKeyframe(data)
	}
	return true
}

// isH264Keyframe 检测 H264 关键帧
func (r *RTSPBridge) isH264Keyframe(data []byte) bool {
	i := 0
	for i < len(data)-4 {
		if data[i] == 0x00 && data[i+1] == 0x00 {
			var nalUnitType byte
			if data[i+2] == 0x00 && data[i+3] == 0x01 {
				if i+4 < len(data) {
					nalUnitType = data[i+4] & 0x1f
				}
			} else if data[i+2] == 0x01 {
				if i+3 < len(data) {
					nalUnitType = data[i+3] & 0x1f
				}
			}

			// NAL unit type 5 表示 IDR 帧(关键帧)
			if nalUnitType == 5 {
				return true
			}
		}
		i++
	}
	return false
}

// isHEVCKeyframe 检测 HEVC 关键帧
func (r *RTSPBridge) isHEVCKeyframe(data []byte) bool {
	i := 0
	for i < len(data)-6 {
		if data[i] == 0x00 && data[i+1] == 0x00 {
			var nalStart int
			if data[i+2] == 0x00 && data[i+3] == 0x01 {
				nalStart = i + 4
			} else if data[i+2] == 0x01 {
				nalStart = i + 3
			} else {
				i++
				continue
			}

			if nalStart < len(data) {
				nalUnitType := (data[nalStart] >> 1) & 0x3f
				// NAL unit type 16-20 表示关键帧
				if nalUnitType >= 16 && nalUnitType <= 20 {
					return true
				}
			}
		}
		i++
	}
	return false
}

// Run 主循环:连接 WebSocket 并传输数据
func (r *RTSPBridge) Run() error {
	if err := r.StartFFMpeg(); err != nil {
		return fmt.Errorf("start ffmpeg: %w", err)
	}
	defer r.StopFFMpeg()

	if err := r.Login(); err != nil {
		return fmt.Errorf("login: %w", err)
	}

	// 构建 WebSocket URL
	protocol := "wss"
	if strings.HasPrefix(r.baseURL, "http://") {
		protocol = "ws"
	}
	host := strings.TrimPrefix(r.baseURL, "https://")
	host = strings.TrimPrefix(host, "http://")

	wsURL := fmt.Sprintf("%s://%s/api/miot/ws/video_stream?camera_id=%s&channel=%s",
		protocol, host, r.cameraID, r.channel)

	log.Infof("连接miloco wss成功: %s", wsURL)

	// 创建 WebSocket 拨号器
	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
		HandshakeTimeout: 30 * time.Second,
	}

	// 从 HTTP 客户端获取 Cookie
	headers := http.Header{}
	if jar := r.httpClient.Jar; jar != nil {
		u := fmt.Sprintf("%s/api/miot/ws/video_stream", r.baseURL)
		parsedURL, _ := url.Parse(u)
		if parsedURL != nil {
			cookies := jar.Cookies(parsedURL)
			for _, cookie := range cookies {
				headers.Add("Cookie", fmt.Sprintf("%s=%s", cookie.Name, cookie.Value))
			}
		}
	}

	ws, _, err := dialer.Dial(wsURL, headers)
	if err != nil {
		return fmt.Errorf("websocket dial: %w", err)
	}
	defer ws.Close()

	log.Info("WebSocket connected. Streaming data...")

	// 设置读取超时
	ws.SetReadDeadline(time.Now().Add(60 * time.Second))

	for {
		select {
		case <-r.ctx.Done():
			return nil
		default:
		}

		messageType, message, err := ws.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Info("WebSocket connection closed normally")
				return nil
			}
			return fmt.Errorf("read message: %w", err)
		}

		// 重置读取超时
		ws.SetReadDeadline(time.Now().Add(60 * time.Second))

		if messageType == websocket.BinaryMessage {
			dataLen := len(message)
			if dataLen >= 100 {
				log.Debugf("Received binary data: %d bytes", dataLen)
			}

			// 等待关键帧
			if r.waitingForKeyframe {
				if r.IsKeyframe(message) {
					log.Info("服务启动。可以添加到nvr软件...")
					r.waitingForKeyframe = false
				} else {
					log.Debug("Skipping non-keyframe data...")
					continue
				}
			}

			// 写入数据到 FFMpeg stdin
			if err := r.WriteData(message); err != nil {
				log.Errorf("Failed to write data to FFMpeg: %v", err)
				log.Info("Attempting to restart FFMpeg...")

				// 尝试重启 FFMpeg
				r.StopFFMpeg()
				time.Sleep(1 * time.Second)

				if err := r.StartFFMpeg(); err != nil {
					return fmt.Errorf("failed to restart FFMpeg: %w", err)
				}

				// 重新等待关键帧
				r.waitingForKeyframe = true
				log.Info("FFMpeg restarted, waiting for keyframe...")
				continue
			}
		}
	}
}

// WriteData 写入数据到 FFMpeg stdin
func (r *RTSPBridge) WriteData(data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.stdin == nil {
		return fmt.Errorf("stdin is nil, FFMpeg process may have terminated")
	}

	if r.process == nil || r.process.Process == nil {
		return fmt.Errorf("FFMpeg process is not running")
	}

	// 检查进程是否仍在运行
	if r.process.ProcessState != nil && r.process.ProcessState.Exited() {
		return fmt.Errorf("FFMpeg process has exited with code: %d", r.process.ProcessState.ExitCode())
	}

	_, err := r.stdin.Write(data)
	if err != nil {
		return fmt.Errorf("write to stdin failed (pipe may be broken): %w", err)
	}

	return nil
}

// Stop 停止桥接
func (r *RTSPBridge) Stop() {
	r.cancel()
	r.StopFFMpeg()
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Warn("Error loading .env file")
	}
	baseURL := flag.String("base-url", getEnv("MILOCO_BASE_URL", "https://miloco:8000"), "Base URL of the Miloco server")
	username := flag.String("username", getEnv("MILOCO_USERNAME", "admin"), "Login username")
	password := flag.String("password", getEnv("MILOCO_PASSWORD", ""), "Login password (MD5)")
	cameraID := flag.String("camera-id", getEnv("CAMERA_ID", ""), "Camera ID to stream")
	channel := flag.String("channel", getEnv("STREAM_CHANNEL", "0"), "Camera channel")
	videoCodec := flag.String("video-codec", getEnv("VIDEO_CODEC", "hevc"), "Input video codec (hevc or h264)")
	rtspPort := flag.String("rtsp-port", getEnv("RTSP_PORT", "8554"), "RTSP server port")
	onvifPort := flag.String("onvif-port", getEnv("ONVIF_PORT", "8000"), "ONVIF HTTP port")
	debug := flag.Bool("debug", false, "Enable debug logging")

	flag.Parse()

	h := &rtsp.ServerHandler{
		Logger: log,
	}
	h.Server = &gortsplib.Server{
		Handler:           h,
		RTSPAddress:       ":" + *rtspPort,
		UDPRTPAddress:     ":8000",
		UDPRTCPAddress:    ":8001",
		MulticastIPRange:  "224.1.0.0/16",
		MulticastRTPPort:  8002,
		MulticastRTCPPort: 8003,
	}

	ready := make(chan struct{})
	go func() {
		err := h.Server.Start()
		if err != nil {
			panic(err)
		}
		log.Infof("RTSP server started on %s", h.Server.RTSPAddress)
		close(ready)
		err = h.Server.Wait()
		if err != nil {
			panic(err)
		}
	}()

	onvif.Start(onvif.Config{
		HTTPListen: *onvifPort, // ONVIF HTTP 端口
		RTSPPort:   *rtspPort,  // 你的 RTSP 端口
		StreamName: "live",     // 你的流路径 /live
		Logger:     log,        // 你刚才用的 logrus 全局 log
	})

	<-ready
	if *debug {
		log.SetLevel(logrus.DebugLevel)
	}

	if *password == "" {
		log.Error("Password is required")
		os.Exit(1)
	}

	if *cameraID == "" {
		log.Error("Camera ID is required")
		os.Exit(1)
	}

	bridge := NewRTSPBridge(*baseURL, *username, *password, *cameraID, *channel, *videoCodec, *rtspPort)

	// 处理中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Info("Stopped by user")
		bridge.Stop()
		os.Exit(0)
	}()

	if err := bridge.Run(); err != nil {
		log.Errorf("Error: %v", err)
		os.Exit(1)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
