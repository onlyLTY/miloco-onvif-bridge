package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
)

// WSSClient WebSocket 客户端
type WSSClient struct {
	BaseURL         string
	Username        string
	Password        string
	CameraID        string
	Channel         string
	VideoCodec      string
	httpClient      *http.Client
	cookieJar       *cookiejar.Jar
	waitingKeyframe bool
}

// LoginRequest 登录请求结构
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse 登录响应结构
type LoginResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// NewWSSClient 创建新的 WSS 客户端
func NewWSSClient(baseURL, username, password, cameraID, channel, videoCodec string) (*WSSClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}

	client := &WSSClient{
		BaseURL:         baseURL,
		Username:        username,
		Password:        password,
		CameraID:        cameraID,
		Channel:         channel,
		VideoCodec:      videoCodec,
		cookieJar:       jar,
		waitingKeyframe: true,
		httpClient: &http.Client{
			Jar: jar,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: 30 * time.Second,
		},
	}

	return client, nil
}

// Login 登录并获取认证
func (c *WSSClient) Login() error {
	loginURL := fmt.Sprintf("%s/api/auth/login", c.BaseURL)

	loginReq := LoginRequest{
		Username: c.Username,
		Password: c.Password,
	}

	jsonData, err := json.Marshal(loginReq)
	if err != nil {
		return fmt.Errorf("failed to marshal login request: %w", err)
	}

	resp, err := c.httpClient.Post(loginURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login failed: status=%d, body=%s", resp.StatusCode, string(body))
	}

	log.Printf("Login successful: %s", string(body))

	// 检查登录状态
	statusURL := fmt.Sprintf("%s/api/miot/login_status", c.BaseURL)
	statusResp, err := c.httpClient.Get(statusURL)
	if err != nil {
		return fmt.Errorf("login status check failed: %w", err)
	}
	defer statusResp.Body.Close()

	if statusResp.StatusCode != http.StatusOK {
		return fmt.Errorf("login status check failed: status=%d", statusResp.StatusCode)
	}

	return nil
}

// isKeyframe 检查是否为关键帧
func (c *WSSClient) isKeyframe(data []byte) bool {
	if c.VideoCodec == "h264" {
		for i := 0; i < len(data)-4; i++ {
			if data[i] == 0x00 && data[i+1] == 0x00 &&
				((data[i+2] == 0x00 && data[i+3] == 0x01) || data[i+2] == 0x01) {
				var nalUnitType byte
				if data[i+2] == 0x01 {
					nalUnitType = data[i+3] & 0x1f
				} else {
					nalUnitType = data[i+4] & 0x1f
				}
				return nalUnitType == 5
			}
		}
		return false
	} else if c.VideoCodec == "hevc" {
		for i := 0; i < len(data)-6; i++ {
			if data[i] == 0x00 && data[i+1] == 0x00 &&
				((data[i+2] == 0x00 && data[i+3] == 0x01) || data[i+2] == 0x01) {
				var nalStart int
				if data[i+2] == 0x01 {
					nalStart = i + 3
				} else {
					nalStart = i + 4
				}
				nalUnitType := (data[nalStart] >> 1) & 0x3f
				if nalUnitType >= 16 && nalUnitType <= 20 {
					return true
				}
			}
		}
		return false
	}
	return true
}

// Run 运行 WebSocket 拉流
func (c *WSSClient) Run() error {
	// 先登录
	if err := c.Login(); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	// 构建 WebSocket URL
	protocol := "ws"
	if strings.HasPrefix(c.BaseURL, "https") {
		protocol = "wss"
	}
	host := strings.TrimPrefix(c.BaseURL, "https://")
	host = strings.TrimPrefix(host, "http://")

	wsURL := fmt.Sprintf("%s://%s/api/miot/ws/video_stream?camera_id=%s&channel=%s",
		protocol, host, c.CameraID, c.Channel)

	log.Printf("Connecting to WebSocket: %s", wsURL)

	// 设置 WebSocket Dialer
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Jar:             c.cookieJar,
	}

	// 解析 URL 并设置 cookies
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return fmt.Errorf("failed to parse base URL: %w", err)
	}

	// 获取 cookies
	cookies := c.cookieJar.Cookies(u)

	// 设置请求头
	header := http.Header{}
	for _, cookie := range cookies {
		header.Add("Cookie", fmt.Sprintf("%s=%s", cookie.Name, cookie.Value))
	}

	// 连接 WebSocket
	conn, _, err := dialer.Dial(wsURL, header)
	if err != nil {
		return fmt.Errorf("failed to connect to WebSocket: %w", err)
	}
	defer conn.Close()

	log.Println("WebSocket connected. Streaming data...")

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))

	// 读取数据流
	for {
		messageType, data, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Println("WebSocket connection closed normally")
				return nil
			}
			return fmt.Errorf("failed to read message: %w", err)
		}

		// 重置读取超时
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		if messageType == websocket.BinaryMessage {
			dataLen := len(data)
			if dataLen >= 100 {
				log.Printf("Received binary data: %d bytes", dataLen)
			}

			// 等待关键帧
			if c.waitingKeyframe {
				if c.isKeyframe(data) {
					log.Println("Keyframe detected! Starting stream...")
					c.waitingKeyframe = false
				} else {
					log.Println("Skipping non-keyframe data...")
					continue
				}
			}

			// 这里可以处理接收到的视频数据
			// 例如：写入文件、发送到其他服务等
			// processData(data)

		} else {
			log.Printf("Received non-binary message type: %d", messageType)
		}
	}
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	// 命令行参数
	baseURL := flag.String("base-url", getEnv("MILOCO_BASE_URL", "https://miloco:8000"), "Base URL of the server")
	username := flag.String("username", getEnv("MILOCO_USERNAME", "admin"), "Login username")
	password := flag.String("password", getEnv("MILOCO_PASSWORD", ""), "Login password")
	cameraID := flag.String("camera-id", getEnv("CAMERA_ID", ""), "Camera ID to stream")
	channel := flag.String("channel", getEnv("STREAM_CHANNEL", "0"), "Camera channel")
	videoCodec := flag.String("video-codec", getEnv("VIDEO_CODEC", "hevc"), "Video codec (hevc or h264)")

	flag.Parse()

	if *password == "" {
		log.Fatal("Password is required")
	}

	if *cameraID == "" {
		log.Fatal("Camera ID is required")
	}

	// 创建客户端
	client, err := NewWSSClient(*baseURL, *username, *password, *cameraID, *channel, *videoCodec)
	if err != nil {
		log.Fatalf("Failed to create WSS client: %v", err)
	}

	// 运行拉流
	if err := client.Run(); err != nil {
		log.Fatalf("Stream error: %v", err)
	}
}

// getEnv 获取环境变量，如果不存在则返回默认值
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
