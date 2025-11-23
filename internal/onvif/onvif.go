package onvif

import (
	"io"
	"net"
	"net/http"

	"github.com/AlexxIT/go2rtc/pkg/onvif"
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
		log.Warnf("[onvif] unknown path: %s %s", r.Method, r.RequestURI)
		w.WriteHeader(404)
		w.Write([]byte("unknown ONVIF endpoint\n"))
	})

	go func() {
		log.Infof("[onvif] 服务启动。监听端口 %s", cfg.HTTPListen)
		if err := http.ListenAndServe(cfg.HTTPListen, nil); err != nil {
			log.Errorf("[onvif] HTTP server error: %v", err)
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
