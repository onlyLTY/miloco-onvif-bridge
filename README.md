# Miloco ONVIF Bridge

一个将 Miloco 视频流桥接为 RTSP 并暴露 ONVIF 接口的轻量服务，便于接入 NVR、VMS 或家庭自动化平台。

主要特性
- 内置 RTSP 服务，默认监听 8554
- 暴露 ONVIF 设备接口，默认端口 8000（HTTP）
- 支持 H.265(HEVC) / H.264 的直通传输
- 通过环境变量即可完成配置
- 提供 Docker 镜像与 Docker Compose 部署方式
- GitHub Actions 自动构建并发布镜像到Docker Hub

环境变量
- MILOCO_BASE_URL：Miloco 服务基础地址（示例：https://miloco:8000）
- MILOCO_PASSWORD：密码（Miloco设置的6位密码的MD5值）
- CAMERA_ID：需要桥接的相机 ID（必填）
- STREAM_CHANNEL：视频通道编号（默认：0）
- VIDEO_CODEC：输入视频编码 hevc 或 h264（默认：hevc）
- RTSP_PORT： RTSP 端口（默认：8554）
- DEVICE_IP：Docker部署设备的ip，用于ONVIF设备连接（如：192.168.31.66）

快速开始（本机）
1) 准备环境变量（复制 .env.example 为 .env 并填写）  
2) 运行：
   - Go 运行：`go build -o miloco-onvif-bridge . && ./miloco-onvif-bridge`
   - 需要安装 ffmpeg（容器镜像已预置 ffmpeg，无需额外安装）

Docker 运行
- 使用Composer

Docker Compose
- 在 docker/docker-compose.yml 已提供示例：
  - 后台运行：`docker compose up -d`

端口与访问
- RTSP：rtsp://<宿主机IP>:8554/live
- ONVIF（HTTP）：http://<宿主机IP>:8000

CI/CD（GitHub Actions）
- 已配置 .github/workflows/docker-publish.yml
- 当推送到 main/master 或发布符合 vX.Y.Z 格式的 tag 时，自动构建多架构镜像并推送到 0nlylty/miloco-onvif-bridge
- 可从 Actions 日志中查看构建状态，或直接拉取最新镜像

故障排查
- 端口已占用：调整 RTSP/ONVIF 端口或释放宿主机端口
- 无画面：确认 CAMERA_ID、VIDEO_CODEC 配置正确；网络连通；等待关键帧后再拉流
- 认证失败：请检查用户名和密码
- 容器环境：镜像内已预装 ffmpeg，无需额外安装

鸣谢
- [Miloco](https://github.com/XiaoMi/xiaomi-miloco)
- [ffmpeg](https://ffmpeg.org/)
- [gortsplib](https://github.com/bluenviron/gortsplib)
- [micam](https://github.com/miiot/micam)