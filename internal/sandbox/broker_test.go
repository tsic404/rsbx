package sandbox

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"rsbx/internal/rpc"
)

// The broker is the only host directory inside the sandbox. Its socket must
// be private to the caller, and it must relay bytes both ways.
func TestBrokerRelaysAndIsPrivate(t *testing.T) {
	dir := tempDirOutsideTmp(t)
	// A stand-in daemon: it echoes one line back and closes.
	up, err := net.Listen("unix", filepath.Join(dir, "up.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		for {
			c, err := up.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 64)
			n, _ := c.Read(buf)
			c.Write([]byte("echo:" + string(buf[:n])))
			c.Close()
		}
	}()

	b, err := newBroker(rpc.Target{Socket: filepath.Join(dir, "up.sock")}, filepath.Join(dir, "broker"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Stop()

	fi, err := os.Stat(filepath.Join(dir, "broker", "daemon.sock"))
	if err != nil {
		t.Fatalf("broker socket missing: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("broker socket mode %o, want 600", fi.Mode().Perm())
	}

	conn, err := net.Dial("unix", filepath.Join(dir, "broker", "daemon.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("ping"))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no relayed reply: %v", err)
	}
	if string(buf[:n]) != "echo:ping" {
		t.Errorf("relayed %q", buf[:n])
	}
}

// A broker whose upstream refuses must not hang the client: the connection
// simply closes.
func TestBrokerFailsFastWhenDaemonDown(t *testing.T) {
	dir := tempDirOutsideTmp(t)
	b, err := newBroker(rpc.Target{Socket: filepath.Join(dir, "missing.sock")}, filepath.Join(dir, "broker"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Stop()
	conn, err := net.Dial("unix", filepath.Join(dir, "broker", "daemon.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("x"))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("dead daemon left the connection open")
	}
}
