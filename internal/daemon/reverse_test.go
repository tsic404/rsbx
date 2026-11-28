package daemon

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rsbx/internal/proto"
)

// socketTestRoot returns a short, absolute directory to build socket fixtures
// in. A unix socket path is limited to about 100 bytes, so the root stays under
// /tmp when that is usable, and it never inherits the host TMPDIR verbatim: a
// relative host TMPDIR would make MkdirTemp hand back a relative path and fail
// these tests for a reason unrelated to the daemon.
func socketTestRoot(t *testing.T) string {
	t.Helper()
	bases := []string{"/tmp"}
	if dir := os.TempDir(); filepath.IsAbs(dir) {
		bases = append(bases, dir)
	}
	var lastErr error
	for _, base := range bases {
		root, err := os.MkdirTemp(base, "rsbx-t-")
		if err != nil {
			lastErr = err
			continue
		}
		t.Cleanup(func() { os.RemoveAll(root) })
		return root
	}
	t.Fatalf("create socket test root: %v", lastErr)
	return ""
}

// handshake performs one reverse handshake over a pipe and returns the channel
// end plus the socket the daemon published.
func handshake(t *testing.T) (net.Conn, string, func()) {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		(&Server{}).ReverseHandshake(server, nil)
	}()
	client.SetReadDeadline(time.Now().Add(10 * time.Second))
	frame, err := proto.ReadFrame(client)
	if err != nil {
		client.Close()
		<-done
		t.Fatalf("read handshake reply: %v", err)
	}
	if frame.Type != proto.TReady {
		client.Close()
		<-done
		t.Fatalf("handshake reply type = %#x, want TReady (payload %q)", frame.Type, frame.Payload)
	}
	stop := func() {
		client.Close()
		<-done
	}
	return client, string(frame.Payload), stop
}

// exerciseStubCall connects to the published socket and drives one stub request
// through the channel, which is the path a real `rsbx-stub` takes.
func exerciseStubCall(t *testing.T, channel net.Conn, socket string) {
	t.Helper()
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatalf("dial published socket: %v", err)
	}
	defer conn.Close()
	req := &proto.ExecReq{Target: "/bin/true", Argv: []string{"/bin/true"}}
	if err := proto.WriteFrame(conn, proto.TExec, req.Encode()); err != nil {
		t.Fatalf("write stub request: %v", err)
	}
	channel.SetReadDeadline(time.Now().Add(10 * time.Second))
	frame, err := proto.ReadFrame(channel)
	if err != nil {
		t.Fatalf("read relayed request: %v", err)
	}
	if frame.Type != proto.TExecLocal || len(frame.Payload) < 4 {
		t.Fatalf("relayed frame type = %#x, want TExecLocal", frame.Type)
	}
	id := binary.BigEndian.Uint32(frame.Payload)
	body := make([]byte, 5)
	binary.BigEndian.PutUint32(body, id)
	body[4] = proto.TExit
	if err := proto.WriteFrame(channel, proto.TLocalData, append(body, proto.ExitPayload(0)...)); err != nil {
		t.Fatalf("write exit frame: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	reply, err := proto.ReadFrame(conn)
	if err != nil {
		t.Fatalf("read stub reply: %v", err)
	}
	if reply.Type != proto.TExit {
		t.Fatalf("stub reply type = %#x, want TExit", reply.Type)
	}
}

// The stub only accepts an absolute socket path, so the daemon must publish one
// even when the environment hands it a relative temp directory. A relative
// TMPDIR used to produce "relative/rsbx-stub-xxxx/session.sock", which the stub
// rejected as "missing absolute RSBX_STUB_SOCKET" although the channel was up.
func TestReverseHandshakePublishesAbsoluteSocketUnderRelativeTMPDIR(t *testing.T) {
	base := socketTestRoot(t)
	resolved, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(base)
	t.Setenv("TMPDIR", "relative-tmp")
	if err := os.Mkdir("relative-tmp", 0o700); err != nil {
		t.Fatal(err)
	}

	client, socket, stop := handshake(t)
	if !filepath.IsAbs(socket) {
		stop()
		t.Fatalf("published socket %q is not absolute", socket)
	}
	if got, want := filepath.Dir(filepath.Dir(socket)), filepath.Join(resolved, "relative-tmp"); got != want {
		stop()
		t.Fatalf("socket directory = %q, want it under %q", got, want)
	}
	if info, err := os.Stat(socket); err != nil {
		stop()
		t.Fatalf("published socket is not there: %v", err)
	} else if info.Mode()&os.ModeSocket == 0 {
		stop()
		t.Fatalf("published path %q is not a socket", socket)
	}
	exerciseStubCall(t, client, socket)

	stop()
	if _, err := os.Stat(socket); !os.IsNotExist(err) {
		t.Fatalf("socket %q survived the handshake: %v", socket, err)
	}
}

// A TMPDIR whose symlink is followed by ".." is resolved by the kernel against
// the link target, not lexically. Binding, publishing or cleaning the lexical
// path would name a directory MkdirTemp never created. The published socket and
// the cleanup must both stay on the actual directory, and nothing may be left
// behind after the handshake.
func TestReverseHandshakeCleansTheDirectoryItCreatedUnderSymlinkedTMPDIR(t *testing.T) {
	base := socketTestRoot(t)
	resolved, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(resolved, "work")
	outside := filepath.Join(resolved, "outside")
	deep := filepath.Join(resolved, "deep")
	for _, dir := range []string{work, outside, deep} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(work, "link")); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)
	// Not filepath.Join: the kernel, not a lexical clean, decides what
	// "link/../deep" means, and MkdirTemp keeps the string it was given.
	t.Setenv("TMPDIR", "link/../deep")

	client, socket, stop := handshake(t)
	if !filepath.IsAbs(socket) {
		stop()
		t.Fatalf("published socket %q is not absolute", socket)
	}
	if got := filepath.Dir(filepath.Dir(socket)); got != deep {
		stop()
		t.Fatalf("socket directory = %q, want the created directory under %q", got, deep)
	}
	if info, err := os.Stat(socket); err != nil {
		stop()
		t.Fatalf("published socket is not there: %v", err)
	} else if info.Mode()&os.ModeSocket == 0 {
		stop()
		t.Fatalf("published path %q is not a socket", socket)
	}
	// The lexical path (work/deep) is not what the kernel created; resolving it
	// lexically would have bound there or cleaned there.
	if _, err := os.Stat(filepath.Join(work, "deep")); !os.IsNotExist(err) {
		stop()
		t.Fatalf("the lexical TMPDIR path exists: %v", err)
	}
	exerciseStubCall(t, client, socket)

	stop()
	if _, err := os.Stat(socket); !os.IsNotExist(err) {
		t.Fatalf("socket %q survived the handshake: %v", socket, err)
	}
	entries, err := os.ReadDir(deep)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the created directory %q left %d entries behind", deep, len(entries))
	}
}

// An absolute TMPDIR that is a short alias for a longer directory already names
// the created directory correctly. Expanding it would only lengthen the socket
// path, so an alias that fits must keep fitting: the handshake, a stub
// connection through it and the cleanup all stay on the alias.
func TestReverseHandshakeKeepsShortAbsoluteTMPDIRAlias(t *testing.T) {
	root := socketTestRoot(t)
	// The target is long enough that its own "session.sock" would not fit a
	// unix socket path, while the alias keeps it well inside the limit.
	target := filepath.Join(root, "a-rather-long-target-directory-name-for-the-alias", "and-one-more-level")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "t")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	// A stub socket path is "<dir>/rsbx-stub-<digits>/session.sock"; 100 bytes
	// is the portable limit (sun_path is 108 on Linux).
	const stubSuffix = "/rsbx-stub-0000000000/session.sock"
	if got := len(target) + len(stubSuffix); got <= 100 {
		t.Fatalf("the expanded path is %d bytes, which still fits the socket limit", got)
	}
	if got := len(alias) + len(stubSuffix); got > 100 {
		t.Fatalf("the alias path is %d bytes and does not fit the socket limit", got)
	}
	t.Setenv("TMPDIR", alias)

	client, socket, stop := handshake(t)
	if !filepath.IsAbs(socket) {
		stop()
		t.Fatalf("published socket %q is not absolute", socket)
	}
	if !strings.HasPrefix(socket, alias+string(os.PathSeparator)) {
		stop()
		t.Fatalf("published socket %q was expanded away from the alias %q", socket, alias)
	}
	if info, err := os.Stat(socket); err != nil {
		stop()
		t.Fatalf("published socket is not there: %v", err)
	} else if info.Mode()&os.ModeSocket == 0 {
		stop()
		t.Fatalf("published path %q is not a socket", socket)
	}
	exerciseStubCall(t, client, socket)

	stop()
	if _, err := os.Stat(socket); !os.IsNotExist(err) {
		t.Fatalf("socket %q survived the handshake: %v", socket, err)
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the alias target %q left %d entries behind", target, len(entries))
	}
}
