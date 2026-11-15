package daemon

import (
	"net"
	"sync"

	"rsbx/internal/fsremote"
	"rsbx/internal/proto"
)

// serveFS answers filesystem requests on a dedicated connection. Each
// connection gets its own fsremote.Server: it owns the descriptor table and
// the kernel locks, so one connection's failure must not leak either across
// clients.
//
// The connection reader never handles a request inline. A blocking lock wait
// (FxSetlkw) must be cancellable, which is only possible if the reader keeps
// accepting frames (and the final Close) instead of being stuck inside one
// Handle. Requests are dispatched to goroutines and reply frames serialized
// under a mutex, since the server is concurrency safe but a connection is not.
func (s *Server) serveFS(c net.Conn, first proto.Frame) {
	fs := fsremote.NewServer()
	var wg sync.WaitGroup
	var wmu sync.Mutex
	write := func(resp *proto.FxResp) bool {
		wmu.Lock()
		defer wmu.Unlock()
		return proto.WriteFrame(c, proto.TFxResp, resp.Encode()) == nil
	}
	dispatch := func(req *proto.FxReq) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// A failed reply write means the client is gone: close the
			// connection so the reader unblocks and fs.Close() below cancels
			// any pending waiting operations. Closing an already closed
			// net.Conn is a harmless no-op.
			if !write(fs.Handle(req)) {
				c.Close()
			}
		}()
	}

	f := first
	for {
		req, err := proto.DecodeFxReq(f.Payload)
		if err != nil {
			break
		}
		dispatch(req)
		var err2 error
		f, err2 = proto.ReadFrame(c)
		if err2 != nil || f.Type != proto.TFxReq {
			break
		}
	}
	// The connection is gone: cancel waiting operations (which unblocks any
	// FxSetlkw handlers) and wait for in-flight handlers to settle so locks and
	// descriptors are not torn down under them.
	fs.Close()
	wg.Wait()
}
