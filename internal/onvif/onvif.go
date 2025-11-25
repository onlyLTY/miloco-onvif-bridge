package onvif

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/AlexxIT/go2rtc/pkg/onvif"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

// Config 用来配置 ONVIF Server
type Config struct {
	// HTTP 监听地址，比如 ":8000"
	HTTPListen string

	// RTSP 端口，比如 "8554"
	RTSPPort string

	// 流的名字，比如 "live"
	StreamName string

	// 日志，不传则用一个新的 logrus.Logger
	Logger *logrus.Logger

	// 设备ip
	DeviceIP string
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// NVR 一般不会带浏览器的 Origin，这里直接放行
		return true
	},
}

// Start 启动 ONVIF HTTP 服务（异步，不阻塞）
func Start(cfg Config) error {
	log := cfg.Logger
	if log == nil {
		log = logrus.New()
		log.SetLevel(logrus.InfoLevel)
	}

	if cfg.HTTPListen == "" {
		cfg.HTTPListen = ":8000"
	}
	if cfg.RTSPPort == "" {
		cfg.RTSPPort = "8554"
	}
	if cfg.StreamName == "" {
		cfg.StreamName = "live"
	}

	// 我们只暴露两个路径：device_service 和 media_service
	// 实际上很多客户端会访问 /onvif/device_service 即可
	handler := makeHandler(cfg, log)
	http.HandleFunc("/onvif/device_service", handler)
	http.HandleFunc("/onvif/media_service", handler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 先判断是不是 WebSocket 握手请求
		if websocket.IsWebSocketUpgrade(r) {
			log.Infof("[onvif] WebSocket upgrade 请求: %s %s", r.Method, r.URL.Path)

			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				log.Errorf("[onvif] WebSocket upgrade 失败: %v", err)
				return
			}

			log.Infof("[onvif] WebSocket 已连接，path=%s", r.URL.Path)

			// 简单读写一下，防止立刻断开，可以顺便看对端发了什么
			go func() {
				defer conn.Close()

				for {
					mt, msg, err := conn.ReadMessage()
					if err != nil {
						log.Infof("[onvif] WebSocket 连接关闭 path=%s err=%v", r.URL.Path, err)
						return
					}
					log.Debugf("[onvif] WS 收到消息 path=%s type=%d msg=%s", r.URL.Path, mt, string(msg))

					// 回个心跳之类的，防止 NVR 报错
					if err := conn.WriteMessage(websocket.TextMessage, []byte("ok")); err != nil {
						log.Errorf("[onvif] WS 写入失败 path=%s err=%v", r.URL.Path, err)
						return
					}
				}
			}()

			return
		}

		// 不是 WebSocket，就按原来的 404 处理
		log.Warnf("[onvif] unknown path: %s %s", r.Method, r.RequestURI)
		w.WriteHeader(404)
		_, _ = w.Write([]byte("unknown ONVIF endpoint\n"))
	})

	go func() {
		log.Infof("[onvif] 服务启动。监听端口 %s", cfg.HTTPListen)
		if err := http.ListenAndServe(cfg.HTTPListen, nil); err != nil {
			log.Errorf("[onvif] HTTP server error: %v", err)
		}
	}()

	go func() {
		log.Infof("[wsd] WS-Discovery 服务启动 (UDP 3702)")
		if err := startWSDiscovery(cfg, log); err != nil {
			log.Errorf("[wsd] WS-Discovery error: %v", err)
		}
	}()

	return nil
}

func makeHandler(cfg Config, log *logrus.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		log.Debugf("[onvif] request %s %s %s", r.Method, r.RequestURI, string(b))

		operation := onvif.GetRequestAction(b)
		if operation == "" {
			http.Error(w, "malformed request body", http.StatusBadRequest)
			return
		}

		log.Debugf("[onvif] request %s %s: %s", r.Method, r.RequestURI, string(b))

		var resp []byte

		switch operation {
		// 一些设备信息 / 网络配置相关
		case onvif.DeviceGetNetworkInterfaces,
			onvif.DeviceGetSystemDateAndTime,
			onvif.DeviceGetDiscoveryMode,
			onvif.DeviceGetDNS,
			onvif.DeviceGetHostname,
			onvif.DeviceGetNetworkDefaultGateway,
			onvif.DeviceGetNetworkProtocols,
			onvif.DeviceGetNTP,
			onvif.DeviceGetScopes:
			resp = onvif.StaticResponse(operation)

		case onvif.DeviceGetCapabilities:
			// 告诉客户端我们的 Media 服务地址
			resp = onvif.GetCapabilitiesResponse(r.Host)

		case onvif.DeviceGetServices:
			resp = onvif.GetServicesResponse(r.Host)

		case onvif.DeviceGetDeviceInformation:
			// 序列号等信息随便写一点
			resp = onvif.GetDeviceInformationResponse(
				"onlyLTY", // SerialNumber
				"miloco",  // Model
				"1.0.0",   // Firmware
				r.Host,    // HardwareId 中通常会包含 host
			)

		case onvif.ServiceGetServiceCapabilities:
			resp = onvif.GetMediaServiceCapabilitiesResponse()

		case onvif.MediaGetVideoSources:
			// 我们就假装只有一个视频源：StreamName
			resp = onvif.GetVideoSourcesResponse([]string{cfg.StreamName})

		case onvif.MediaGetProfiles:
			// 同样只报告一个 profile，token=StreamName
			resp = onvif.GetProfilesResponse([]string{cfg.StreamName})

		case onvif.MediaGetProfile:
			token := onvif.FindTagValue(b, "ProfileToken")
			if token == "" {
				token = cfg.StreamName
			}
			resp = onvif.GetProfileResponse(token)

		case onvif.MediaGetVideoSourceConfigurations:
			resp = onvif.GetVideoSourceConfigurationsResponse([]string{cfg.StreamName})

		case onvif.MediaGetVideoSourceConfiguration:
			token := onvif.FindTagValue(b, "ConfigurationToken")
			if token == "" {
				token = cfg.StreamName
			}
			resp = onvif.GetVideoSourceConfigurationResponse(token)

		case onvif.MediaGetStreamUri:
			// ONVIF 客户端通过这个拿 RTSP URL
			host, _, err := net.SplitHostPort(r.Host)
			if err != nil {
				// 如果没端口，直接用 Host
				host = r.Host
			}
			// 不管 ProfileToken 为啥，一律返回同一条流
			uri := "rtsp://" + host + ":" + cfg.RTSPPort + "/" + cfg.StreamName
			log.Infof("[onvif] GetStreamUri -> %s", uri)
			resp = onvif.GetStreamUriResponse(uri)

		case onvif.MediaGetSnapshotUri:
			// 你可以以后实现一个 /snapshot 接口，这里先给个占位符 URI
			snapURI := "http://" + r.Host + "/snapshot.jpg"
			resp = onvif.GetSnapshotUriResponse(snapURI)

		default:
			log.Warnf("[onvif] unsupported operation: %s", operation)
			http.Error(w, "unsupported operation", http.StatusBadRequest)
			return
		}

		log.Debugf("[onvif] response: %s", string(resp))

		w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
		if _, err = w.Write(resp); err != nil {
			log.Errorf("[onvif] write response error: %v", err)
		}
	}
}

// startWSDiscovery 作为 WS-Discovery 服务端：
// 监听 0.0.0.0:3702，收到 Probe 就回 ProbeMatches
func startWSDiscovery(cfg Config, log *logrus.Logger) error {
	addr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: 3702,
	}

	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	log.Infof("[wsd] listening on %s", addr.String())

	buf := make([]byte, 8192)

	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Errorf("[wsd] ReadFromUDP error: %v", err)
			continue
		}

		data := buf[:n]
		text := string(data)

		// 只处理包含 Probe 的请求，其他忽略
		if !strings.Contains(text, "Probe") {
			log.Debugf("[wsd] 收到非 Probe 请求: %s", text)
			continue
		}

		log.Infof("[wsd] 收到 Probe 来自 %s", remote.String())

		reply := buildProbeMatches(cfg, text)

		if _, err := conn.WriteToUDP([]byte(reply), remote); err != nil {
			log.Errorf("[wsd] WriteToUDP error: %v", err)
			continue
		}

		log.Infof("[wsd] 已回复 ProbeMatches 给 %s", remote.String())
	}
}

// buildProbeMatches 根据收到的 Probe XML 构造最小可用的 ProbeMatches 响应
func buildProbeMatches(cfg Config, probeXML string) string {
	// 对方的 MessageID → 放到 RelatesTo 里，规范一点
	relatesTo := onvif.FindTagValue([]byte(probeXML), "MessageID")
	if relatesTo == "" {
		relatesTo = "urn:uuid:" + onvif.UUID()
	}

	// 自己的 EPR（随便一个 UUID）
	endpoint := "urn:uuid:" + onvif.UUID()
	messageID := "urn:uuid:" + onvif.UUID()

	ip := cfg.DeviceIP
	if ip == "" {
		ip = "127.0.0.1"
		logrus.Warnf("Device IP not provided, using default: %s", ip)
	}

	port := strings.TrimPrefix(cfg.HTTPListen, ":")
	if port == "" {
		port = "8000"
	}

	xaddrs := fmt.Sprintf("http://%s:%s/onvif/device_service", ip, port)

	// 非常简化的 ProbeMatches，够大多数 NVR/客户端用
	reply := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope
  xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"
  xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <SOAP-ENV:Header>
    <wsa:MessageID>%s</wsa:MessageID>
    <wsa:RelatesTo>%s</wsa:RelatesTo>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</wsa:Action>
  </SOAP-ENV:Header>
  <SOAP-ENV:Body>
    <wsd:ProbeMatches>
      <wsd:ProbeMatch>
        <wsa:EndpointReference>
          <wsa:Address>%s</wsa:Address>
        </wsa:EndpointReference>
        <wsd:Types>dn:NetworkVideoTransmitter</wsd:Types>
        <wsd:Scopes>
          onvif://www.onvif.org/name/miloco-bridge
          onvif://www.onvif.org/location/local
          onvif://www.onvif.org/type/Network_Video_Transmitter
        </wsd:Scopes>
        <wsd:XAddrs>%s</wsd:XAddrs>
        <wsd:MetadataVersion>1</wsd:MetadataVersion>
      </wsd:ProbeMatch>
    </wsd:ProbeMatches>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>`, messageID, relatesTo, endpoint, xaddrs)

	return reply
}
