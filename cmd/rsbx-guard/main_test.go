//go:build linux

package main

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestGuardAcceptsOnlyFixedDescriptorArguments(t *testing.T) {
	valid := []string{"/bin/rsbx-guard", "-rsbx-guard-spec-fd", "3", "-rsbx-guard-gate-fd", "4"}
	if err := checkGuardArgs(valid); err != nil {
		t.Fatal(err)
	}
	invalid := [][]string{nil, {}, valid[:4], append(slices.Clone(valid), "extra")}
	for i := range valid {
		args := slices.Clone(valid)
		args[i] = ""
		invalid = append(invalid, args)
	}
	for _, replacement := range []struct {
		index int
		value string
	}{{1, "-rsbx-guard-gate-fd"}, {2, "03"}, {2, "9"}, {3, "-rsbx-guard-spec-fd"}, {4, "3"}} {
		args := slices.Clone(valid)
		args[replacement.index] = replacement.value
		invalid = append(invalid, args)
	}
	for _, argv := range invalid {
		if err := checkGuardArgs(argv); err == nil || !strings.Contains(err.Error(), "expected") {
			t.Fatalf("malformed guard argv accepted: %#v, err=%v", argv, err)
		}
	}
}

func TestGuardGateRequiresExactlyOneReleaseByteAndEOF(t *testing.T) {
	for _, body := range []string{"1", "", "0", "11", "1\n", "x1"} {
		t.Run(body, func(t *testing.T) {
			var fds [2]int
			if err := unix.Pipe(fds[:]); err != nil {
				t.Fatal(err)
			}
			if body != "" {
				if n, err := unix.Write(fds[1], []byte(body)); err != nil || n != len(body) {
					unix.Close(fds[0])
					unix.Close(fds[1])
					t.Fatalf("write gate: n=%d err=%v", n, err)
				}
			}
			if err := unix.Close(fds[1]); err != nil {
				unix.Close(fds[0])
				t.Fatal(err)
			}
			err := readGuardGate(fds[0])
			if (err == nil) != (body == "1") {
				t.Fatalf("gate %q returned %v", body, err)
			}
			if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
				t.Fatalf("gate descriptor was not consumed: %v", err)
			}
		})
	}
	if err := readGuardGate(-1); err == nil {
		t.Fatal("negative gate descriptor accepted")
	}
}

func TestGuardPinsExecutingThreadAndNeverReadsControlEnvironment(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate guard source")
	}
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(filepath.Dir(testFile), "main.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var main *ast.FuncDecl
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == "main" {
			main = function
		}
	}
	if main == nil || len(main.Body.List) == 0 {
		t.Fatal("guard main is missing")
	}
	first, ok := main.Body.List[0].(*ast.ExprStmt)
	if !ok {
		t.Fatal("first guard operation does not pin the OS thread")
	}
	call, ok := first.X.(*ast.CallExpr)
	if !ok {
		t.Fatal("first guard operation is not a call")
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		t.Fatal("first guard call does not pin the OS thread")
	}
	pkg, ok := selector.X.(*ast.Ident)
	if !ok || pkg.Name != "runtime" || selector.Sel.Name != "LockOSThread" {
		t.Fatal("guard does not call runtime.LockOSThread first")
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
		case "Getenv", "LookupEnv", "Environ", "ExpandEnv":
			t.Errorf("guard reads control environment through os.%s", selector.Sel.Name)
		}
		return true
	})
}
