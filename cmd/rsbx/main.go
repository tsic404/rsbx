// Command rsbx gives the caller a shell whose stdout, filesystem and child
// processes live on the daemon — except the programs listed in local.allow.
//
// The first thing main does is check whether this process was started as the
// sandbox launcher. That path exits into the entry program and never reaches
// the flag package, so the internal launch flag cannot collide with any
// user-visible option.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"rsbx/internal/config"
	"rsbx/internal/proto"
	"rsbx/internal/sandbox"
)

// installGoroutineDump writes every goroutine's stack to the file named by
// RSBX_STACK_FILE when SIGUSR2 arrives. It has to be a file: the stalled
// session holds the mount, so its own stderr may be unreadable by the time the
// dump is wanted, and the caller that needs it is outside the sandbox.
func installGoroutineDump() {
	path := os.Getenv("RSBX_STACK_FILE")
	if path == "" {
		return
	}
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGUSR2)
	go func() {
		for range sigc {
			buf := make([]byte, 4<<20)
			n := runtime.Stack(buf, true)
			f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				continue
			}
			f.Write(buf[:n])
			f.Close()
		}
	}()
}

// version is injected at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if sandbox.MaybeRunFilesystem() || sandbox.MaybeRunLauncher() {
		return
	}
	installGoroutineDump()
	os.Exit(runCLI())
}

// runCLI owns a session until cleanup has completed. Returning, rather than
// exiting inside setup paths, makes every error release its owned resources.
func runCLI() (code int) {
	var (
		cfgPath = flag.String("config", "", "configuration file (default ~/.rsbx/config.toml)")
		noMount = flag.Bool("no-mount", false, "print the computed plan and exit")
		serve   = flag.Bool("serve", false, "serve a session filesystem until interrupted")
		showVer = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()
	if *showVer {
		fmt.Println("rsbx", version)
		return 0
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(sigc)
	go func() {
		select {
		case sig := <-sigc:
			cancel(interrupted{sig.(syscall.Signal)})
		case <-ctx.Done():
		}
	}()
	exe, err := os.Executable()
	if err != nil {
		return report(err)
	}
	exeDir, err := filepath.EvalSymlinks(filepath.Dir(exe))
	if err != nil {
		return report(fmt.Errorf("resolve helper directory: %w", err))
	}
	path := *cfgPath
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return report(err)
		}
		path = filepath.Join(home, ".rsbx", "config.toml")
	}
	cfg, err := config.Load(path)
	if err != nil {
		return report(fmt.Errorf("%s: %w", path, err))
	}
	plan, err := sandbox.Prepare(cfg, exeDir)
	if err != nil {
		return report(err)
	}
	defer func() {
		if err := plan.Close(); err != nil {
			_ = report(fmt.Errorf("session cleanup: %w", err))
			if code == 0 {
				code = 1
			}
		}
	}()
	if *noMount {
		fmt.Print(plan.Explain())
		return 0
	}
	// Probe outside FUSE on the controller's own connection. The goroutine
	// captures this Plan's connection once: Close nils Plan.Remote, so a read
	// of the field from another goroutine races with cleanup.
	remote := plan.Remote
	probe := make(chan error, 1)
	go func() {
		_, err := remote.Do(&proto.FxReq{Op: proto.FxStat, Path: "/"})
		probe <- err
	}()
	select {
	case err := <-probe:
		if err != nil {
			return report(fmt.Errorf("daemon unreachable (%s): %w", cfg.Daemon.EffectiveEndpoint(), err))
		}
	case <-ctx.Done():
		if err := remote.Close(); err != nil {
			_ = report(fmt.Errorf("close session connection: %w", err))
		}
		return interruptedCode(ctx)
	}
	if err := plan.StartFilesystem(ctx); err != nil {
		if ctx.Err() != nil {
			// StartFilesystem already released the session. A bare
			// cancellation is the expected outcome; a cleanup or worker fault
			// joined alongside it must still be reported.
			if err != ctx.Err() {
				_ = report(fmt.Errorf("start session filesystem: %w", err))
			}
			return interruptedCode(ctx)
		}
		return report(err)
	}
	if *serve {
		select {
		case <-ctx.Done():
			return interruptedCode(ctx)
		case <-plan.FilesystemDone():
			return report(fmt.Errorf("filesystem worker exited during the session"))
		}
	}
	argv := flag.Args()
	if len(argv) == 0 {
		argv = []string{cfg.Local.Entry}
	}
	type result struct {
		code int
		err  error
	}
	finished := make(chan result, 1)
	go func() {
		code, err := plan.Run(ctx, argv)
		finished <- result{code, err}
	}()
	select {
	case r := <-finished:
		if r.err != nil {
			return report(r.err)
		}
		return r.code
	case <-ctx.Done():
		code = interruptedCode(ctx)
	case <-plan.FilesystemDone():
		cancel(fmt.Errorf("filesystem worker exited during the session"))
		code = report(context.Cause(ctx))
	}
	// Release this session's own RPC waits before joining the launcher: a
	// handler blocked on the daemon keeps the mount busy, so waiting for the
	// launcher first could hang. Errors are reported once by the deferred
	// Close, which owns the same connection and the same worker.
	_ = plan.Remote.Close()
	_ = plan.StopFilesystem()
	select {
	case <-finished:
	case <-time.After(8 * time.Second):
		_ = report(fmt.Errorf("launcher did not finish session shutdown"))
		// A stalled join is a shutdown fault, but it must not replace a
		// status that already carries a terminating signal.
		if code == 0 {
			code = 1
		}
	}
	return code
}

type interrupted struct{ signal syscall.Signal }

func (e interrupted) Error() string { return e.signal.String() }

func interruptedCode(ctx context.Context) int {
	if sig, ok := context.Cause(ctx).(interrupted); ok {
		return 128 + int(sig.signal)
	}
	return 1
}

func report(err error) int {
	fmt.Fprintln(os.Stderr, "rsbx:", err)
	return 1
}
