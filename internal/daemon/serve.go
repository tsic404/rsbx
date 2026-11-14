package daemon

import (
	"net"

	"rsbx/internal/fsremote"
	"rsbx/internal/proto"
)

// serveFS answers filesystem requests on a dedicated connection.
func (s *Server) serveFS(c net.Conn, first proto.Frame) {
	fs := &fsremote.Server{Root: s.Root}
	f := first
	for {
		req, err := proto.DecodeFxReq(f.Payload)
		if err != nil {
			return
		}
		resp := fs.Handle(req)
		if proto.WriteFrame(c, proto.TFxResp, resp.Encode()) != nil {
			return
		}
		var err2 error
		f, err2 = proto.ReadFrame(c)
		if err2 != nil || f.Type != proto.TFxReq {
			return
		}
	}
}
