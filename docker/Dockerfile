# ---- Build stage ----
FROM golang:1.25-alpine AS builder

WORKDIR /src

# 仅复制依赖清单以利用缓存
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# 复制剩余源码
COPY . .

# 由 buildx 传入目标平台参数
ARG TARGETOS
ARG TARGETARCH

# 构建单个 main 包（注意是 "."，不是 "./..."）
RUN --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/miloco-onvif-bridge .

# ---- Runtime stage ----
FROM debian:bookworm-slim

# 安装运行时依赖与 ffmpeg
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg ca-certificates tzdata && \
    rm -rf /var/lib/apt/lists/*

# 复制构建产物
COPY --from=builder /out/miloco-onvif-bridge /usr/local/bin/miloco-onvif-bridge

# 暴露端口（RTSP、ONVIF HTTP、RTP/RTCP 多播/单播 UDP）
EXPOSE 8554/tcp 8000/tcp 8000/udp 8001/udp 8002/udp 8003/udp

# 默认环境变量（可在运行时覆盖）
ENV MILOCO_BASE_URL=https://miloco:8000 \
    MILOCO_USERNAME=admin \
    MILOCO_PASSWORD="" \
    CAMERA_ID=000000000 \
    STREAM_CHANNEL=0 \
    VIDEO_CODEC=hevc \
    RTSP_PORT=8554

ENTRYPOINT ["/usr/local/bin/miloco-onvif-bridge"]
