package fusefs

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	gofs "github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"rsbx/internal/fsremote"
	"rsbx/internal/proto"
)

type countingBackend struct {
	fsRemote
	calls [256]atomic.Uint64
}

func TestProbeExternalRename(t *testing.T) {
	mount, root, _ := remoteMount(t)
	name := filepath.Join(root, "document")
	view := filepath.Join(mount, name)
	if _, err := os.Stat(view); !os.IsNotExist(err) {
		t.Fatalf("expected ENOENT: %v", err)
	}
	if err := os.WriteFile(name, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	held, err := os.Open(view)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := os.WriteFile(name+".next", []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(name+".next", name); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(view)
	t.Logf("immediate reopen: %q %v", data, err)
	time.Sleep(1100 * time.Millisecond)
	data, err = os.ReadFile(view)
	if err != nil || string(data) != "new" {
		t.Fatalf("after TTL: %q %v", data, err)
	}
	buf := make([]byte, 3)
	if _, err := held.ReadAt(buf, 0); err != nil || string(buf) != "old" {
		t.Fatalf("old fd: %q %v", buf, err)
	}
}

func (remote *countingBackend) Do(req *proto.FxReq) (*proto.FxResp, error) {
	remote.calls[req.Op].Add(1)
	time.Sleep(15 * time.Millisecond)
	return remote.fsRemote.Do(req)
}

func TestCountRemoteWalk(t *testing.T) {
	for _, ttl := range []time.Duration{0, time.Second} {
		t.Run(ttl.String(), func(t *testing.T) {
			tree := t.TempDir()
			for directory := range 10 {
				base := filepath.Join(tree, fmt.Sprint(directory))
				if err := os.Mkdir(base, 0700); err != nil {
					t.Fatal(err)
				}
				for file := range 8 {
					if err := os.WriteFile(filepath.Join(base, fmt.Sprint(file)), []byte("small"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			remote := &countingBackend{fsRemote: fsRemote{s: fsremote.NewServer()}}
			defer remote.s.Close()
			node := NewRoot(&Layout{Local: noLocal{}, Remote: remote})
			defer node.Close()
			mount := t.TempDir()
			zero := time.Duration(0)
			server, err := gofs.Mount(mount, node, &gofs.Options{EntryTimeout: &ttl, AttrTimeout: &ttl, NegativeTimeout: &zero, NullPermissions: true, MountOptions: fuse.MountOptions{EnableLocks: true, DisableSplice: true}})
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			err = filepath.Walk(filepath.Join(mount, tree), func(path string, info fs.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return err
				}
				data, err := os.ReadFile(path)
				if err == nil && string(data) != "small" {
					return fmt.Errorf("wrong content for %s", path)
				}
				return err
			})
			elapsed := time.Since(start)
			if unmountErr := server.Unmount(); unmountErr != nil {
				t.Fatal(unmountErr)
			}
			server.Wait()
			if err != nil {
				t.Fatal(err)
			}
			var total uint64
			for op := range remote.calls {
				if count := remote.calls[op].Load(); count != 0 {
					t.Logf("op=%d calls=%d", op, count)
					total += count
				}
			}
			t.Logf("total=%d wall=%v", total, elapsed)
		})
	}
}
