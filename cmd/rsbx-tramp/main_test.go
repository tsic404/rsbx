//go:build linux && (amd64 || arm64)

package main

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"rsbx/internal/proto"
	"rsbx/internal/pty"
)

// This is a test-binary subprocess entrypoint, not a production self-test or
// environment-controlled bypass in rsbx-tramp.
func TestGatewayExitStatusHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "--rsbx-test-exit-code" {
		return
	}
	code, err := strconv.Atoi(os.Args[len(os.Args)-1])
	if err != nil {
		t.Fatal(err)
	}
	if code < 0 {
		if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
			t.Fatal(err)
		}
		sig := syscall.Signal(-code)
		if sig != syscall.SIGKILL {
			runtime.LockOSThread()
			// Exercise cleanup of a Go handler and an inherited blocked mask.
			channel := make(chan os.Signal, 1)
			signal.Notify(channel, sig)
			mask := uint64(1) << uint(sig-1)
			_, _, errno := unix.RawSyscall6(unix.SYS_RT_SIGPROCMASK, unix.SIG_BLOCK,
				uintptr(unsafe.Pointer(&mask)), 0, 8, 0, 0)
			if errno != 0 {
				t.Fatal(errno)
			}
		}
	}
	if err := exitGatewayStatus(code); err != nil {
		t.Fatal(err)
	}
	t.Fatal("exitGatewayStatus returned without exiting")
}

func TestGatewayPreservesNormalAndNegativeSignalStatus(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []int{0, 37, 255, -int(syscall.SIGTERM), -int(syscall.SIGINT),
		-int(syscall.SIGKILL), -int(syscall.SIGQUIT), -64} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, executable, "-test.run=^TestGatewayExitStatusHelper$",
				"--", "--rsbx-test-exit-code", strconv.Itoa(code))
			command.Dir = t.TempDir()
			output, err := command.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("status propagation timed out: %s", output)
			}
			if command.ProcessState == nil {
				t.Fatalf("helper did not start: %v: %s", err, output)
			}
			status, ok := command.ProcessState.Sys().(syscall.WaitStatus)
			if !ok {
				t.Fatal("helper returned no Linux wait status")
			}
			if code >= 0 {
				if !status.Exited() || status.ExitStatus() != code {
					t.Fatalf("normal status %d became %v: %s", code, status, output)
				}
			} else if !status.Signaled() || status.Signal() != syscall.Signal(-code) {
				t.Fatalf("signal status %d became %v: %s", code, status, output)
			}
		})
	}
}

func TestGatewayRejectsInvalidNonterminatingSignalStatuses(t *testing.T) {
	for _, code := range []int{-65, -2147483648, -int(syscall.SIGSTOP), -int(syscall.SIGCONT),
		-int(syscall.SIGCHLD), -int(syscall.SIGWINCH)} {
		if err := exitGatewayStatus(code); err == nil {
			t.Fatalf("invalid negative status %d accepted", code)
		}
	}
}

func ttyTestRequest() *proto.ExecReq {
	return &proto.ExecReq{
		Target: "/captured/target",
		Argv:   []string{"not-the-target", "arg"},
		Env:    []string{"A=captured", "RSBX_TRAMP_TARGET=/evil", "RSBX_TRAMP_CMD=evil"},
		Dir:    "/captured/cwd",
		TTY:    true,
		Rows:   12,
		Cols:   13,
	}
}

func TestGatewayDoesNotTreatNullCharacterDeviceAsTTY(t *testing.T) {
	device, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	req := ttyTestRequest()
	if err := configureGatewayTTY(req, device, device); err != nil {
		t.Fatal(err)
	}
	want := ttyTestRequest()
	want.TTY, want.Rows, want.Cols = false, 0, 0
	if !reflect.DeepEqual(req, want) {
		t.Fatalf("nonterminal detection changed captured fields or retained TTY: %#v", req)
	}
}

func TestGatewayReadsActualTerminalSizeAndPreservesRequest(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	if err := pty.SetWinsize(slave, 41, 113); err != nil {
		t.Fatal(err)
	}
	req := ttyTestRequest()
	if err := configureGatewayTTY(req, slave, slave); err != nil {
		t.Fatal(err)
	}
	want := ttyTestRequest()
	want.TTY, want.Rows, want.Cols = true, 41, 113
	if !reflect.DeepEqual(req, want) {
		t.Fatalf("TTY detection did not preserve capture and real size: %#v", req)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	if err := configureGatewayTTY(req, slave, writer); err != nil {
		t.Fatal(err)
	}
	if req.TTY || req.Rows != 0 || req.Cols != 0 {
		t.Fatal("redirected stdout was treated as a terminal")
	}
}

func TestGatewayUsesCapturedRequestFixedBrokerAndInheritedStdio(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate gateway command source")
	}
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(filepath.Dir(testFile), "main.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var capturedRequest, fixedSession bool
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if ok {
			if pkg, ok := selector.X.(*ast.Ident); ok && pkg.Name == "os" {
				switch selector.Sel.Name {
				case "Getenv", "LookupEnv", "Environ", "ExpandEnv", "Getwd", "Readlink", "Executable":
					t.Errorf("gateway command derives launch state through os.%s", selector.Sel.Name)
				}
			}
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok = call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}
		if pkg.Name == "sandbox" && selector.Sel.Name == "ReadGatewayRequest" {
			capturedRequest = len(call.Args) == 0
		}
		if pkg.Name != "rpc" || selector.Sel.Name != "RunSessionContext" {
			return true
		}
		if len(call.Args) != 6 {
			t.Fatal("gateway session no longer has context, target, request and inherited stdio")
		}
		target, ok := call.Args[1].(*ast.CompositeLit)
		if !ok || len(target.Elts) != 1 {
			t.Fatal("gateway session transport is not a fixed socket target")
		}
		entry, ok := target.Elts[0].(*ast.KeyValueExpr)
		if !ok {
			t.Fatal("gateway target is not keyed by Socket")
		}
		key, ok := entry.Key.(*ast.Ident)
		if !ok || key.Name != "Socket" {
			t.Fatal("gateway transport can select a command")
		}
		value, ok := entry.Value.(*ast.SelectorExpr)
		if !ok {
			t.Fatal("gateway socket does not use sandbox.BrokerSock")
		}
		owner, ok := value.X.(*ast.Ident)
		if !ok || owner.Name != "sandbox" || value.Sel.Name != "BrokerSock" {
			t.Fatal("gateway socket does not use sandbox.BrokerSock")
		}
		request, ok := call.Args[2].(*ast.Ident)
		if !ok || request.Name != "req" {
			t.Fatal("gateway session does not pass the captured request")
		}
		for i, name := range []string{"Stdin", "Stdout", "Stderr"} {
			stream, ok := call.Args[i+3].(*ast.SelectorExpr)
			if !ok {
				t.Fatalf("gateway does not inherit %s", name)
			}
			owner, ok := stream.X.(*ast.Ident)
			if !ok || owner.Name != "os" || stream.Sel.Name != name {
				t.Fatalf("gateway does not inherit %s", name)
			}
		}
		fixedSession = true
		return true
	})
	if !capturedRequest || !fixedSession {
		t.Fatal("gateway command lost its captured request or fixed broker session")
	}
}
