// Package rpc is the client side of the daemon connection: one multiplexed
// control connection for filesystem requests, plus one connection per exec
// session (so a long running process never head-of-line blocks stat calls).
package rpc

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"rsbx/internal/proto"
)

// Target describes how to reach the daemon.
type Target struct {
	// Socket is a unix socket path, used when Command is empty.
	Socket string
	// Command, when set, starts a stdio daemon (e.g. an ssh invocation).
	Command []string
}

// Dial opens a raw connection to the daemon.
func (t Target) Dial() (net.Conn, error) {
	if len(t.Command) == 0 {
		return net.Dial("unix", t.Socket)
	}
	cmd := exec.Command(t.Command[0], t.Command[1:]...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, err
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		return nil, err
	}
	s := &stdioConn{r: stdout, w: stdin, cmd: cmd, done: make(chan struct{})}
	go func() {
		cmd.Wait()
		close(s.done)
	}()
	return s, nil
}

// stdioConn exposes a pair of pipes as a net.Conn.
type stdioConn struct {
	r    io.ReadCloser
	w    io.WriteCloser
	cmd  *exec.Cmd
	done chan struct{}
}

func (s *stdioConn) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *stdioConn) Write(p []byte) (int, error) { return s.w.Write(p) }
func (s *stdioConn) Close() error {
	s.w.Close()
	s.r.Close()
	if s.cmd.Process != nil {
		s.cmd.Process.Kill()
	}
	// Wait for the child to be reaped; the process is gone once its pipes
	// close, so this never outlives the connection.
	<-s.done
	return nil
}
func (s *stdioConn) LocalAddr() net.Addr              { return nil }
func (s *stdioConn) RemoteAddr() net.Addr             { return nil }
func (s *stdioConn) SetDeadline(time.Time) error      { return nil }
func (s *stdioConn) SetReadDeadline(time.Time) error  { return nil }
func (s *stdioConn) SetWriteDeadline(time.Time) error { return nil }

// FS is a multiplexed filesystem client.
type FS struct {
	target  Target
	mu      sync.Mutex
	conn    net.Conn
	gen     uint64 // connection generation; bumped whenever conn changes
	wmu     sync.Mutex
	next    atomic.Uint32
	pending map[uint32]chan *proto.FxResp
}

// NewFS returns a client that connects lazily.
func NewFS(t Target) *FS {
	return &FS{target: t, pending: make(map[uint32]chan *proto.FxResp)}
}

// Do performs one filesystem request.
func (c *FS) Do(req *proto.FxReq) (*proto.FxResp, error) {
	ch, id, conn, err := c.register()
	if err != nil {
		return nil, err
	}
	req.ID = id
	c.wmu.Lock()
	werr := proto.WriteFrame(conn, proto.TFxReq, req.Encode())
	c.wmu.Unlock()
	if werr != nil {
		c.fail(id)
		c.dropConn(conn)
		return nil, werr
	}
	resp, ok := <-ch
	if !ok {
		return nil, errors.New("rsbx: filesystem connection lost")
	}
	if resp.Kind == proto.KErr || resp.Errno != 0 {
		errno := syscall.Errno(resp.Errno)
		if errno == 0 {
			errno = errnoOf(resp.Err)
		}
		return resp, errno
	}
	return resp, nil
}

// errnoOf maps a daemon error string onto a syscall.Errno.
func errnoOf(s string) syscall.Errno {
	for _, e := range []syscall.Errno{
		syscall.EPERM, syscall.ENOENT, syscall.EACCES, syscall.EEXIST,
		syscall.ENOTDIR, syscall.EISDIR, syscall.EINVAL, syscall.ENOSPC,
		syscall.EROFS, syscall.ENAMETOOLONG, syscall.ENOTEMPTY, syscall.EBUSY,
		syscall.EXDEV, syscall.EIO,
	} {
		if e.Error() == s {
			return e
		}
	}
	return syscall.EIO
}

func (c *FS) register() (chan *proto.FxResp, uint32, net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		conn, err := c.target.Dial()
		if err != nil {
			return nil, 0, nil, fmt.Errorf("rsbx: connect to daemon: %w", err)
		}
		c.conn = conn
		c.gen++
		go c.readLoop(conn, c.gen)
	}
	id := c.next.Add(1)
	ch := make(chan *proto.FxResp, 1)
	c.pending[id] = ch
	return ch, id, c.conn, nil
}

func (c *FS) readLoop(conn net.Conn, gen uint64) {
	for {
		f, err := proto.ReadFrame(conn)
		if err != nil {
			// Only the reader of the current generation may reset the
			// connection; a stale reader from a replaced connection must not
			// fail requests that belong to the newer one.
			c.dropConnGen(conn, gen)
			return
		}
		if f.Type != proto.TFxResp {
			continue
		}
		resp, err := proto.DecodeFxResp(f.Payload)
		if err != nil {
			continue
		}
		c.mu.Lock()
		ch := c.pending[resp.ID]
		delete(c.pending, resp.ID)
		c.mu.Unlock()
		if ch != nil {
			ch <- resp
		}
	}
}

func (c *FS) fail(id uint32) {
	c.mu.Lock()
	ch := c.pending[id]
	delete(c.pending, id)
	c.mu.Unlock()
	if ch != nil {
		close(ch)
	}
}

// dropConn closes conn and fails all pending requests, but only if conn is
// still the current connection. A write failure or reader EOF from an already
// replaced connection is a no-op.
func (c *FS) dropConn(conn net.Conn) {
	c.mu.Lock()
	if c.conn != conn {
		c.mu.Unlock()
		return
	}
	c.conn = nil
	c.gen++
	pending := c.pending
	c.pending = make(map[uint32]chan *proto.FxResp)
	c.mu.Unlock()
	conn.Close()
	for _, ch := range pending {
		close(ch)
	}
}

func (c *FS) dropConnGen(conn net.Conn, gen uint64) {
	c.mu.Lock()
	if c.conn != conn || c.gen != gen {
		c.mu.Unlock()
		return
	}
	c.conn = nil
	c.gen++
	pending := c.pending
	c.pending = make(map[uint32]chan *proto.FxResp)
	c.mu.Unlock()
	conn.Close()
	for _, ch := range pending {
		close(ch)
	}
}

// Close shuts the shared connection down and fails every waiting request.
func (c *FS) Close() error {
	c.mu.Lock()
	conn := c.conn
	c.conn = nil
	c.gen++
	pending := c.pending
	c.pending = make(map[uint32]chan *proto.FxResp)
	c.mu.Unlock()
	var err error
	if conn != nil {
		err = conn.Close()
	}
	for _, ch := range pending {
		close(ch)
	}
	return err
}

// ReadFile fetches a whole remote file body via handle open/read/close.
func (c *FS) ReadFile(p string) ([]byte, proto.Attr, error) {
	resp, err := c.Do(&proto.FxReq{
		Op:    proto.FxOpen,
		Path:  p,
		Flags: uint32(syscall.O_RDONLY),
	})
	if err != nil {
		return nil, proto.Attr{}, err
	}
	if resp.Kind == proto.KNone {
		return nil, proto.Attr{}, os.ErrNotExist
	}
	if resp.Kind != proto.KHandle || resp.Handle == 0 {
		return nil, proto.Attr{}, syscall.EIO
	}
	h := resp.Handle
	defer c.Do(&proto.FxReq{Op: proto.FxClose, Handle: h})

	st, err := c.Do(&proto.FxReq{Op: proto.FxFstat, Handle: h})
	if err != nil {
		return nil, proto.Attr{}, err
	}
	attr := st.Attr

	var buf []byte
	for off := int64(0); ; {
		r, err := c.Do(&proto.FxReq{
			Op:     proto.FxPread,
			Handle: h,
			Offset: off,
			Size:   proto.MaxIO,
		})
		if err != nil {
			return nil, proto.Attr{}, err
		}
		n := int64(len(r.Data))
		if r.Count > 0 && int64(r.Count) < n {
			n = int64(r.Count)
		}
		if n == 0 {
			break
		}
		buf = append(buf, r.Data[:n]...)
		off += n
		if n < proto.MaxIO {
			break
		}
	}
	return buf, attr, nil
}

// WriteFile replaces a remote file body via handle open/write/close.
func (c *FS) WriteFile(p string, data []byte) error {
	resp, err := c.Do(&proto.FxReq{
		Op:    proto.FxOpen,
		Path:  p,
		Flags: uint32(syscall.O_WRONLY | syscall.O_CREAT | syscall.O_TRUNC),
		Mode:  0o644,
	})
	if err != nil {
		return err
	}
	if resp.Kind != proto.KHandle || resp.Handle == 0 {
		return syscall.EIO
	}
	h := resp.Handle
	defer c.Do(&proto.FxReq{Op: proto.FxClose, Handle: h})

	for off := 0; off < len(data); {
		end := off + proto.MaxIO
		if end > len(data) {
			end = len(data)
		}
		if _, err := c.Do(&proto.FxReq{
			Op:     proto.FxPwrite,
			Handle: h,
			Offset: int64(off),
			Data:   data[off:end],
		}); err != nil {
			return err
		}
		off = end
	}
	return nil
}
