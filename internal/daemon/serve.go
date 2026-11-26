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
//
// A connection may open with TSession to name the session it belongs to. The
// daemon then announces that session's command starts on this connection, so a
// view stops answering from results a command it ran may have invalidated. A
// connection without the frame answers for itself, as before.
func (s *Server) serveFS(c net.Conn, first proto.Frame) {
	fs := fsremote.NewServer()
	var wg sync.WaitGroup
	var wmu sync.Mutex
	writeFrame := func(typ byte, p []byte) bool {
		wmu.Lock()
		defer wmu.Unlock()
		return proto.WriteFrame(c, typ, p) == nil
	}
	write := func(resp *proto.FxResp) bool {
		return writeFrame(proto.TFxResp, resp.Encode())
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
	var token string
	var sess *session
	if f.Type == proto.TSession {
		tok, err := proto.DecodeSessionPayload(f.Payload)
		if err != nil || tok == "" {
			return
		}
		token = tok
		sess = s.sessions.acquire(token)
		fs.UseSession(sess)
	}
	var sub *sessionSub
	if sess != nil {
		// The subscription write shares the reply mutex, so an announcement and
		// the replies around it keep their order on this connection.
		sub = sess.subscribe(func(epoch uint64, names []string) bool {
			return writeFrame(proto.TInvalidate, proto.InvalidatePayload(epoch, names))
		})
		defer sess.unsubscribe(sub)
		defer s.sessions.release(token, sess)
		// Adopt the session's current epoch before serving: a reconnected view
		// starts from the session's state, not from zero.
		if !writeFrame(proto.TInvalidate, proto.InvalidatePayload(sess.currentEpoch(), nil)) {
			fs.Close()
			wg.Wait()
			return
		}
		var err error
		f, err = proto.ReadFrame(c)
		if err != nil {
			fs.Close()
			wg.Wait()
			return
		}
	}
	for {
		if f.Type == proto.TFxReq {
			req, err := proto.DecodeFxReq(f.Payload)
			if err != nil {
				break
			}
			dispatch(req)
		}
		var err2 error
		f, err2 = proto.ReadFrame(c)
		if err2 != nil {
			break
		}
	}
	// The connection is gone: cancel waiting operations (which unblocks any
	// FxSetlkw handlers) and wait for in-flight handlers to settle so locks and
	// descriptors are not torn down under them.
	fs.Close()
	wg.Wait()
}
