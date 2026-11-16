//go:build linux

package sandbox

import (
	"bytes"
	"encoding/binary"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"golang.org/x/sys/unix"

	"rsbx/internal/proto"
)

func gatewayTestRequest() *proto.ExecReq {
	return &proto.ExecReq{
		Target: "/captured/daemon-target/\xff",
		Argv:   []string{"refused-argv0", "", "arg with spaces", "\xff\xfe"},
		Env: []string{
			"PATH=/captured", "RSBX_TRAMP_SOCK=/evil", "RSBX_TRAMP_CMD=evil",
			"RSBX_TRAMP_TARGET=/evil", "RSBX_TRAMP_SELFTEST=1", "RSBX_TRAMP_REQFD=9",
			"RSBX_LOCAL_TREES=/evil", "BYTES=\xff\xfe",
		},
		Dir:  "/captured/cwd/\xff",
		TTY:  true,
		Rows: 37,
		Cols: 91,
	}
}

func gatewayTestServer(t *testing.T, dir string) *gatewayServer {
	t.Helper()
	server, err := newGatewayServer(filepath.Join(dir, "gateway.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("close gateway server: %v", err)
		}
	})
	return server
}

func dialGatewayTest(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		t.Fatal("gateway connection is not a Unix socket")
	}
	return unixConn
}

func TestGatewayPublishesImmutableRequestForPeerPID(t *testing.T) {
	t.Setenv("RSBX_TRAMP_SOCK", "/override")
	t.Setenv("RSBX_TRAMP_CMD", "override")
	t.Setenv("RSBX_TRAMP_TARGET", "/override")
	server := gatewayTestServer(t, tempDirOutsideTmp(t))
	request := gatewayTestRequest()
	if err := server.Publish(os.Getpid(), request); err != nil {
		t.Fatal(err)
	}
	// The caller's record and its slices are no longer the source of truth.
	request.Target = "/mutated"
	request.Argv[0] = "mutated"
	request.Env[0] = "PATH=/mutated"
	request.Dir = "/mutated"
	request.TTY, request.Rows, request.Cols = false, 1, 2
	got, err := readGatewayFrame(dialGatewayTest(t, server.listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	want := gatewayTestRequest()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("captured request changed: got %#v, want %#v", got, want)
	}
	if _, err := readGatewayFrame(dialGatewayTest(t, server.listener.Addr().String())); err == nil ||
		!strings.Contains(err.Error(), "consumed") {
		t.Fatalf("request replayed: %v", err)
	}
	if err := server.Publish(os.Getpid(), want); err == nil {
		t.Fatal("consumed PID republished before Forget")
	}
	server.Forget(os.Getpid())
	if _, err := readGatewayFrame(dialGatewayTest(t, server.listener.Addr().String())); err == nil ||
		!strings.Contains(err.Error(), "no captured") {
		t.Fatalf("forgotten request served: %v", err)
	}
}

func TestGatewayRejectsUnregisteredAndDuplicatePIDs(t *testing.T) {
	dir := tempDirOutsideTmp(t)
	server := gatewayTestServer(t, dir)
	if err := server.Publish(os.Getpid()+1, gatewayTestRequest()); err != nil {
		t.Fatal(err)
	}
	if _, err := readGatewayFrame(dialGatewayTest(t, filepath.Join(dir, "gateway.sock"))); err == nil ||
		!strings.Contains(err.Error(), "no captured") {
		t.Fatalf("different PID served another process's request: %v", err)
	}
	req := gatewayTestRequest()
	if err := server.Publish(os.Getpid(), req); err != nil {
		t.Fatal(err)
	}
	if err := server.Publish(os.Getpid(), req); err == nil || !strings.Contains(err.Error(), "already") {
		t.Fatalf("duplicate publish accepted: %v", err)
	}
	server.Forget(os.Getpid())
	if err := server.Publish(os.Getpid(), req); err != nil {
		t.Fatalf("republish after Forget: %v", err)
	}
	for _, bad := range []int{0, -1} {
		if err := server.Publish(bad, req); err == nil {
			t.Fatalf("PID %d accepted", bad)
		}
	}
}

func TestGatewayRejectsMalformedPublishedRequests(t *testing.T) {
	server := gatewayTestServer(t, tempDirOutsideTmp(t))
	for _, tc := range []struct {
		name   string
		mutate func(*proto.ExecReq)
	}{
		{name: "missing_request"},
		{"empty_target", func(r *proto.ExecReq) { r.Target = "" }},
		{"nul_target", func(r *proto.ExecReq) { r.Target = "/bad\x00target" }},
		{"empty_argv", func(r *proto.ExecReq) { r.Argv = nil }},
		{"nul_argv", func(r *proto.ExecReq) { r.Argv[0] = "bad\x00arg" }},
		{"nul_env", func(r *proto.ExecReq) { r.Env[0] = "A=\x00" }},
		{"relative_dir", func(r *proto.ExecReq) { r.Dir = "relative" }},
		{"empty_dir", func(r *proto.ExecReq) { r.Dir = "" }},
		{"nul_dir", func(r *proto.ExecReq) { r.Dir = "/bad\x00dir" }},
		{"oversized_input", func(r *proto.ExecReq) { r.Env = []string{strings.Repeat("x", maxGatewayRequestSize+1)} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var req *proto.ExecReq
			if tc.mutate != nil {
				req = gatewayTestRequest()
				tc.mutate(req)
			}
			if err := server.Publish(os.Getpid(), req); err == nil {
				t.Fatal("malformed captured request published")
			}
		})
	}
}

func TestGatewayRejectsUnauthorizedCredentialsWithoutConsuming(t *testing.T) {
	server := gatewayTestServer(t, tempDirOutsideTmp(t))
	if err := server.Publish(os.Getpid(), gatewayTestRequest()); err != nil {
		t.Fatal(err)
	}
	for _, peer := range []*unix.Ucred{
		nil,
		{Pid: 0, Uid: server.uid, Gid: server.gid},
		{Pid: int32(os.Getpid() + 1), Uid: server.uid, Gid: server.gid},
		{Pid: int32(os.Getpid()), Uid: server.uid ^ 1, Gid: server.gid},
		{Pid: int32(os.Getpid()), Uid: server.uid, Gid: server.gid ^ 1},
	} {
		if body, err := server.takeRequest(peer); err == nil || body != nil {
			t.Fatalf("unauthorized credentials %#v consumed a request", peer)
		}
	}
	if _, err := readGatewayFrame(dialGatewayTest(t, server.listener.Addr().String())); err != nil {
		t.Fatalf("unauthorized peers consumed the legitimate request: %v", err)
	}
}

func gatewayTestWire(status byte, size uint32, body []byte) []byte {
	wire := make([]byte, 5+len(body))
	wire[0] = status
	binary.BigEndian.PutUint32(wire[1:5], size)
	copy(wire[5:], body)
	return wire
}

func TestGatewayBoundedFramingRejectsTruncatedAndOversized(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire []byte
		eof  error
	}{
		{"empty", nil, io.EOF},
		{"short_header", []byte{0, 0, 0}, io.ErrUnexpectedEOF},
		{"bad_status", gatewayTestWire(7, 1, []byte{'x'}), nil},
		{"zero_length", gatewayTestWire(gatewayStatusOK, 0, nil), nil},
		{"oversized_request", gatewayTestWire(gatewayStatusOK, maxGatewayRequestSize+1, nil), nil},
		{"oversized_error", gatewayTestWire(gatewayStatusError, maxGatewayErrorSize+1, nil), nil},
		{"truncated_body", gatewayTestWire(gatewayStatusOK, 5, []byte{'x'}), io.ErrUnexpectedEOF},
		{"malformed_request", gatewayTestWire(gatewayStatusOK, 3, []byte("{}}")), nil},
		{"wrong_version", gatewayTestWire(gatewayStatusOK, 1, []byte{1}), nil},
		{"truncated_request", gatewayTestWire(gatewayStatusOK, 1, []byte{2}), io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readGatewayFrame(bytes.NewReader(tc.wire))
			if err == nil {
				t.Fatal("malformed frame accepted")
			}
			if tc.eof != nil && !errors.Is(err, tc.eof) {
				t.Fatalf("EOF error %v was not preserved: %v", tc.eof, err)
			}
		})
	}
	if err := writeGatewayFrame(nil, gatewayStatusError, make([]byte, maxGatewayErrorSize+1)); err == nil {
		t.Fatal("oversized error frame written")
	}
	if err := writeGatewayFrame(nil, gatewayStatusOK, make([]byte, maxGatewayRequestSize+1)); err == nil {
		t.Fatal("oversized request frame written")
	}
	if err := writeGatewayFrame(nil, gatewayStatusOK, nil); err == nil {
		t.Fatal("empty success frame written")
	}
	if err := writeGatewayFrame(nil, 9, []byte{'x'}); err == nil {
		t.Fatal("invalid status frame written")
	}
}

type gatewayChunkWriter struct {
	bytes.Buffer
}

func (w *gatewayChunkWriter) Write(body []byte) (int, error) {
	return w.Buffer.Write(body[:min(2, len(body))])
}

type gatewayZeroWriter struct{}

func (gatewayZeroWriter) Write([]byte) (int, error) { return 0, nil }

func TestGatewayFrameRoundTripHandlesPartialIO(t *testing.T) {
	req := gatewayTestRequest()
	body := req.Encode()
	var writer gatewayChunkWriter
	if err := writeGatewayFrame(&writer, gatewayStatusOK, body); err != nil {
		t.Fatal(err)
	}
	got, err := readGatewayFrame(iotest.OneByteReader(bytes.NewReader(writer.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, req) {
		t.Fatalf("round trip changed: got %#v, want %#v", got, req)
	}
	if err := writeGatewayFrame(gatewayZeroWriter{}, gatewayStatusOK, body); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero-progress writer returned %v", err)
	}
	var failure bytes.Buffer
	const reason = "peer has no captured request"
	if err := writeGatewayFrame(&failure, gatewayStatusError, []byte(reason)); err != nil {
		t.Fatal(err)
	}
	if req, err := readGatewayFrame(&failure); err == nil || req != nil || !strings.Contains(err.Error(), reason) {
		t.Fatalf("explicit supervisor error was lost: req=%#v err=%v", req, err)
	}
}

func TestGatewayFrameAllowsExactSizeLimitAndRejectsTrailingData(t *testing.T) {
	req := gatewayTestRequest()
	body := req.Encode()
	trailing := append(bytes.Clone(body), 'x')
	if _, err := readGatewayFrame(bytes.NewReader(gatewayTestWire(gatewayStatusOK, uint32(len(trailing)), trailing))); err == nil {
		t.Fatal("trailing binary data accepted")
	}
	req.Env[0] += strings.Repeat("x", maxGatewayRequestSize-len(body))
	body = req.Encode()
	if len(body) != maxGatewayRequestSize {
		t.Fatalf("exact-bound fixture size %d", len(body))
	}
	got, err := readGatewayFrame(bytes.NewReader(gatewayTestWire(gatewayStatusOK, uint32(len(body)), body)))
	if err != nil || !reflect.DeepEqual(got, req) {
		t.Fatalf("exact-bound frame rejected or changed: req=%#v err=%v", got, err)
	}
}

func TestGatewayCloseJoinsActiveWorkers(t *testing.T) {
	dir := tempDirOutsideTmp(t)
	server := gatewayTestServer(t, dir)
	req := gatewayTestRequest()
	req.Env = []string{"DATA=" + strings.Repeat("x", maxGatewayRequestSize-2048)}
	if err := server.Publish(os.Getpid(), req); err != nil {
		t.Fatal(err)
	}
	conn := dialGatewayTest(t, filepath.Join(dir, "gateway.sock"))
	var header [5]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		t.Fatal(err)
	}
	// Leave the large body unread while Close cancels the response worker.
	closed := make(chan error, 1)
	go func() { closed <- server.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not join active response workers")
	}
	server.mu.Lock()
	active := len(server.conns)
	server.mu.Unlock()
	if active != 0 {
		t.Fatalf("Close left %d active connections", active)
	}
	var callers sync.WaitGroup
	for range 4 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			if err := server.Close(); err != nil {
				t.Errorf("repeated Close: %v", err)
			}
		}()
	}
	callers.Wait()
	if err := server.Publish(os.Getpid()+1, gatewayTestRequest()); err == nil {
		t.Fatal("publish on closed server accepted")
	}
	if conn, err := net.DialTimeout("unix", filepath.Join(dir, "gateway.sock"), time.Second); err == nil {
		conn.Close()
		t.Fatal("closed server accepted a connection")
	}
}

func TestReadGatewayRequestUsesOnlyFixedSocket(t *testing.T) {
	if GatewayRequestSock != "/dev/.rsbx-exec.sock" {
		t.Fatalf("gateway path changed: %s", GatewayRequestSock)
	}
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate gateway source")
	}
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(filepath.Dir(testFile), "gateway_linux.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fixedDial bool
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "ReadGatewayRequest" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok || pkg.Name != "net" || selector.Sel.Name != "DialTimeout" {
				return true
			}
			if len(call.Args) != 3 {
				t.Fatal("gateway dial no longer has a fixed timeout")
			}
			path, ok := call.Args[1].(*ast.Ident)
			fixedDial = ok && path.Name == "GatewayRequestSock"
			return true
		})
	}
	if !fixedDial {
		t.Fatal("gateway request client does not dial the fixed socket")
	}
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := selector.X.(*ast.Ident)
		if !ok || pkg.Name != "os" {
			return true
		}
		switch selector.Sel.Name {
		case "Getenv", "LookupEnv", "Environ", "ExpandEnv", "Getwd":
			t.Errorf("gateway request selection reads ambient state through os.%s", selector.Sel.Name)
		}
		return true
	})
}
