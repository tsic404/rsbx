package daemon

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"rsbx/internal/proto"
)

type stubCall struct {
	conn      net.Conn
	input     chan proto.Frame
	interrupt chan struct{}
	done      chan struct{}
	once      sync.Once
}

func (call *stubCall) close() {
	call.once.Do(func() { close(call.interrupt); call.conn.Close(); close(call.done) })
}

type stubSession struct {
	conn    net.Conn
	mu      sync.Mutex
	writeMu sync.Mutex
	calls   map[uint32]*stubCall
	next    uint32
	closed  bool
	wg      sync.WaitGroup
}

func (session *stubSession) send(typ byte, id uint32, payload []byte) error {
	body := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(body, id)
	copy(body[4:], payload)
	session.writeMu.Lock()
	defer session.writeMu.Unlock()
	session.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	return proto.WriteFrame(session.conn, typ, body)
}

func (server *Server) ReverseHandshake(conn net.Conn, payload []byte) {
	if len(payload) != 0 {
		proto.WriteFrame(conn, proto.TErr, []byte("unsupported reverse handshake"))
		return
	}
	dir, err := os.MkdirTemp("", "rsbx-stub-")
	if err != nil {
		proto.WriteFrame(conn, proto.TErr, []byte(err.Error()))
		return
	}
	created := dir
	if !filepath.IsAbs(dir) {
		// The stub accepts only an absolute path, and os.TempDir() passes a
		// relative TMPDIR through unchanged. A lexical Abs would collapse a
		// ".." that follows a symlinked component without following that
		// link, so binding, publishing and cleanup could name a different
		// directory than the one MkdirTemp created. Resolve against the real
		// filesystem first, then make the symlink-free result absolute.
		if dir, err = filepath.EvalSymlinks(dir); err == nil && !filepath.IsAbs(dir) {
			dir, err = filepath.Abs(dir)
		}
		if err != nil {
			os.RemoveAll(created)
			proto.WriteFrame(conn, proto.TErr, []byte("resolve stub socket directory: "+err.Error()))
			return
		}
	}
	// An absolute TMPDIR is already a working name for the directory that was
	// created, and keeping it verbatim preserves a short alias instead of
	// expanding it past the unix socket path limit.
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "session.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		proto.WriteFrame(conn, proto.TErr, []byte(err.Error()))
		return
	}
	defer listener.Close()
	if err = os.Chmod(socket, 0600); err != nil {
		return
	}
	session := &stubSession{conn: conn, calls: map[uint32]*stubCall{}}
	if proto.WriteFrame(conn, proto.TReady, []byte(socket)) != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			incoming, err := listener.Accept()
			if err != nil {
				return
			}
			session.mu.Lock()
			if session.closed || len(session.calls) >= 32 {
				session.mu.Unlock()
				incoming.Close()
				continue
			}
			session.next++
			if session.next == 0 {
				session.next++
			}
			id := session.next
			call := &stubCall{conn: incoming, input: make(chan proto.Frame, 64), interrupt: make(chan struct{}), done: make(chan struct{})}
			session.calls[id] = call
			session.wg.Add(1)
			session.mu.Unlock()
			go session.serveStub(id, call)
		}
	}()
	defer func() {
		listener.Close()
		<-done
		session.mu.Lock()
		session.closed = true
		for _, call := range session.calls {
			call.close()
		}
		session.mu.Unlock()
		session.wg.Wait()
	}()
	for {
		frame, err := proto.ReadFrame(conn)
		if err != nil {
			return
		}
		if frame.Type == proto.TLocalCancel {
			if len(frame.Payload) < 4 {
				return
			}
			id := binary.BigEndian.Uint32(frame.Payload)
			session.mu.Lock()
			call := session.calls[id]
			session.mu.Unlock()
			if call != nil {
				call.close()
			}
			continue
		}
		if frame.Type != proto.TLocalData || len(frame.Payload) < 5 {
			return
		}
		id := binary.BigEndian.Uint32(frame.Payload)
		session.mu.Lock()
		call := session.calls[id]
		session.mu.Unlock()
		if call == nil {
			continue
		}
		incoming := proto.Frame{Type: frame.Payload[4], Payload: frame.Payload[5:]}
		if len(incoming.Payload) > 64<<10 {
			call.conn.Close()
			continue
		}
		select {
		case call.input <- incoming:
		default:
			call.conn.Close()
		}
	}
}

func (session *stubSession) serveStub(id uint32, call *stubCall) {
	defer session.wg.Done()
	defer call.close()
	defer func() { session.mu.Lock(); delete(session.calls, id); session.mu.Unlock() }()
	call.conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	frame, err := proto.ReadFrame(call.conn)
	if err != nil || frame.Type != proto.TExec || len(frame.Payload) > 1<<20 {
		return
	}
	if _, err = proto.DecodeExecReq(frame.Payload); err != nil {
		proto.WriteFrame(call.conn, proto.TErr, []byte(err.Error()))
		proto.WriteFrame(call.conn, proto.TExit, proto.ExitPayload(126))
		return
	}
	call.conn.SetReadDeadline(time.Time{})
	if session.send(proto.TExecLocal, id, frame.Payload) != nil {
		return
	}
	finished := make(chan struct{})
	var output sync.WaitGroup
	output.Add(1)
	go func() {
		defer output.Done()
		for {
			select {
			case <-finished:
				return
			case <-call.interrupt:
				return
			case frame := <-call.input:
				call.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
				if proto.WriteFrame(call.conn, frame.Type, frame.Payload) != nil || frame.Type == proto.TExit {
					call.close()
					return
				}
			}
		}
	}()
	for {
		frame, err = proto.ReadFrame(call.conn)
		if err != nil {
			break
		}
		if frame.Type != proto.TStdin && frame.Type != proto.TSig {
			break
		}
		if frame.Type == proto.TStdin && len(frame.Payload) > 64<<10 {
			break
		}
		body := append([]byte{frame.Type}, frame.Payload...)
		if session.send(proto.TLocalData, id, body) != nil {
			break
		}
	}
	close(finished)
	call.close()
	output.Wait()
	session.send(proto.TLocalCancel, id, nil)
}
