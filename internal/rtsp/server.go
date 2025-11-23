package rtsp

import (
	"sync"

	"github.com/pion/rtp"
	"github.com/sirupsen/logrus"

	"github.com/bluenviron/gortsplib/v5"
	"github.com/bluenviron/gortsplib/v5/pkg/base"
	"github.com/bluenviron/gortsplib/v5/pkg/description"
	"github.com/bluenviron/gortsplib/v5/pkg/format"
)

// This example shows how to:
// 1. create a RTSP server which accepts plain connections.
// 2. allow a single client to publish a stream.
// 3. allow several clients to read the stream.

type ServerHandler struct {
	Server    *gortsplib.Server
	mutex     sync.RWMutex
	stream    *gortsplib.ServerStream
	publisher *gortsplib.ServerSession
	Logger    *logrus.Logger
}

// OnConnOpen called when a connection is opened.
func (sh *ServerHandler) OnConnOpen(_ *gortsplib.ServerHandlerOnConnOpenCtx) {
	sh.Logger.Debug("conn opened")
}

// OnConnClose called when a connection is closed.
func (sh *ServerHandler) OnConnClose(ctx *gortsplib.ServerHandlerOnConnCloseCtx) {
	sh.Logger.Debug("conn closed (%v)", ctx.Error)
}

// OnSessionOpen called when a session is opened.
func (sh *ServerHandler) OnSessionOpen(_ *gortsplib.ServerHandlerOnSessionOpenCtx) {
	sh.Logger.Debug("session opened")
}

// OnSessionClose called when a session is closed.
func (sh *ServerHandler) OnSessionClose(ctx *gortsplib.ServerHandlerOnSessionCloseCtx) {
	sh.Logger.Debug("session closed")

	sh.mutex.Lock()
	defer sh.mutex.Unlock()

	// if the session is the publisher,
	// close the stream and disconnect any reader.
	if sh.stream != nil && ctx.Session == sh.publisher {
		sh.stream.Close()
		sh.stream = nil
	}
}

// OnDescribe called when receiving a DESCRIBE request.
func (sh *ServerHandler) OnDescribe(
	_ *gortsplib.ServerHandlerOnDescribeCtx,
) (*base.Response, *gortsplib.ServerStream, error) {
	sh.Logger.Debug("DESCRIBE request")

	sh.mutex.RLock()
	defer sh.mutex.RUnlock()

	// no one is publishing yet
	if sh.stream == nil {
		return &base.Response{
			StatusCode: base.StatusNotFound,
		}, nil, nil
	}

	// send medias that are being published to the client
	return &base.Response{
		StatusCode: base.StatusOK,
	}, sh.stream, nil
}

// OnAnnounce called when receiving an ANNOUNCE request.
func (sh *ServerHandler) OnAnnounce(ctx *gortsplib.ServerHandlerOnAnnounceCtx) (*base.Response, error) {
	sh.Logger.Debug("ANNOUNCE request")

	sh.mutex.Lock()
	defer sh.mutex.Unlock()

	// disconnect existing publisher
	if sh.stream != nil {
		sh.stream.Close()
		sh.publisher.Close()
	}

	// create the stream and save the publisher
	sh.stream = &gortsplib.ServerStream{
		Server: sh.Server,
		Desc:   ctx.Description,
	}
	err := sh.stream.Initialize()
	if err != nil {
		panic(err)
	}
	sh.publisher = ctx.Session

	return &base.Response{
		StatusCode: base.StatusOK,
	}, nil
}

// OnSetup called when receiving a SETUP request.
func (sh *ServerHandler) OnSetup(ctx *gortsplib.ServerHandlerOnSetupCtx) (
	*base.Response, *gortsplib.ServerStream, error,
) {
	sh.Logger.Debug("SETUP request")

	// SETUP is used by both readers and publishers. In case of publishers, just return StatusOK.
	if ctx.Session.State() == gortsplib.ServerSessionStatePreRecord {
		return &base.Response{
			StatusCode: base.StatusOK,
		}, nil, nil
	}

	sh.mutex.RLock()
	defer sh.mutex.RUnlock()

	// no one is publishing yet
	if sh.stream == nil {
		return &base.Response{
			StatusCode: base.StatusNotFound,
		}, nil, nil
	}

	return &base.Response{
		StatusCode: base.StatusOK,
	}, sh.stream, nil
}

// OnPlay called when receiving a PLAY request.
func (sh *ServerHandler) OnPlay(_ *gortsplib.ServerHandlerOnPlayCtx) (*base.Response, error) {
	sh.Logger.Debug("PLAY request")

	return &base.Response{
		StatusCode: base.StatusOK,
	}, nil
}

// OnRecord called when receiving a RECORD request.
func (sh *ServerHandler) OnRecord(ctx *gortsplib.ServerHandlerOnRecordCtx) (*base.Response, error) {
	sh.Logger.Debug("RECORD request")

	// called when receiving a RTP packet
	ctx.Session.OnPacketRTPAny(func(medi *description.Media, _ format.Format, pkt *rtp.Packet) {
		// route the RTP packet to all readers
		err := sh.stream.WritePacketRTP(medi, pkt)
		if err != nil {
			sh.Logger.Error("ERR: %v", err)
		}
	})

	return &base.Response{
		StatusCode: base.StatusOK,
	}, nil
}
