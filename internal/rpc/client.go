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
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go cmd.Wait()
	return &stdioConn{r: stdout, w: stdin, cmd: cmd}, nil
}

// stdioConn exposes a pair of pipes as a net.Conn.
type stdioConn struct {
	r   io.ReadCloser
	w   io.WriteCloser
	cmd *exec.Cmd
}

func (s *stdioConn) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *stdioConn) Write(p []byte) (int, error) { return s.w.Write(p) }
func (s *stdioConn) Close() error {
	s.w.Close()
	s.r.Close()
	if s.cmd.Process != nil {
		return s.cmd.Process.Kill()
	}
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
	ch, id, err := c.register()
	if err != nil {
		return nil, err
	}
	req.ID = id
	c.wmu.Lock()
	err = proto.WriteFrame(c.conn, proto.TFxReq, req.Encode())
	c.wmu.Unlock()
	if err != nil {
		c.fail(id)
		c.reset()
		return nil, err
	}
	resp, ok := <-ch
	if !ok {
		return nil, errors.New("rsbx: filesystem connection lost")
	}
	return resp, nil
}

func (c *FS) register() (chan *proto.FxResp, uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		conn, err := c.target.Dial()
		if err != nil {
			return nil, 0, fmt.Errorf("rsbx: connect to daemon: %w", err)
		}
		c.conn = conn
		go c.readLoop(conn)
	}
	id := c.next.Add(1)
	ch := make(chan *proto.FxResp, 1)
	c.pending[id] = ch
	return ch, id, nil
}

func (c *FS) readLoop(conn net.Conn) {
	for {
		f, err := proto.ReadFrame(conn)
		if err != nil {
			c.reset()
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

// reset drops the connection and fails every waiting request.
func (c *FS) reset() {
	c.mu.Lock()
	conn := c.conn
	c.conn = nil
	pending := c.pending
	c.pending = make(map[uint32]chan *proto.FxResp)
	c.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
	for _, ch := range pending {
		close(ch)
	}
}

// Close shuts the shared connection down.
func (c *FS) Close() error {
	c.mu.Lock()
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

// ReadFile fetches a whole remote file body.
func (c *FS) ReadFile(p string) ([]byte, proto.Attr, error) {
	resp, err := c.Do(&proto.FxReq{Op: proto.FxRead, Path: p})
	if err != nil {
		return nil, proto.Attr{}, err
	}
	switch resp.Kind {
	case proto.KFile:
		return resp.Data, resp.Attr, nil
	case proto.KNone:
		return nil, proto.Attr{}, os.ErrNotExist
	case proto.KErr:
		return nil, proto.Attr{}, fmt.Errorf("%s", resp.Err)
	}
	return nil, proto.Attr{}, fmt.Errorf("rsbx: unexpected reply %d", resp.Kind)
}

// WriteFile replaces a remote file body.
func (c *FS) WriteFile(p string, data []byte) error {
	resp, err := c.Do(&proto.FxReq{Op: proto.FxWrite, Path: p, Data: data})
	if err != nil {
		return err
	}
	if resp.Kind == proto.KErr {
		return fmt.Errorf("%s", resp.Err)
	}
	return nil
}
