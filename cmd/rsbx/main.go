// Command rsbx gives the caller a shell whose stdout, filesystem and child
// processes live on the daemon — except the programs listed in local.allow.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"rsbx/internal/config"
	"rsbx/internal/proto"
	"rsbx/internal/sandbox"
)

// version is injected at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var (
		cfgPath = flag.String("config", "", "configuration file (default ~/.rsbx/config.toml)")
		noMount = flag.Bool("no-mount", false, "print the computed plan and exit")
		serve   = flag.Bool("serve", false, "mount the sandbox root and stay running (test aid)")
		showVer = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("rsbx", version)
		return
	}

	exe, err := os.Executable()
	if err != nil {
		fatal(err)
	}
	exeDir, err := filepath.EvalSymlinks(filepath.Dir(exe))
	if err != nil {
		exeDir = filepath.Dir(exe)
	}
	path := *cfgPath
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fatal(err)
		}
		path = filepath.Join(home, ".rsbx", "config.toml")
	}
	cfg, err := config.Load(path)
	if err != nil {
		fatal(fmt.Errorf("%s: %w", path, err))
	}
	plan, err := sandbox.Prepare(cfg, exeDir)
	if err != nil {
		fatal(err)
	}
	if *noMount {
		fmt.Print(plan.Explain())
		return
	}
	// make sure the daemon answers before mounting, so a dead daemon is a
	// clear error instead of a hanging filesystem
	if _, err := plan.Remote.Do(&proto.FxReq{Op: proto.FxStat, Path: "/"}); err != nil {
		fatal(fmt.Errorf("daemon unreachable (%s): %w", cfg.Daemon.EffectiveEndpoint(), err))
	}
	srv, err := plan.MountRoot()
	if err != nil {
		fatal(fmt.Errorf("mount %s: %w", plan.Mount, err))
	}
	// os.Exit skips defers, so the filesystem would stay mounted and the mount
	// point would answer ENOTCONN on the next run. Unmount before every exit
	// path instead of relying on the defer.
	unmounted := false
	stop := func() {
		if unmounted {
			return
		}
		unmounted = true
		srv.Unmount()
	}
	defer stop()
	if os.Getenv("RSBX_DEBUG_MOUNT") != "" {
		ents, err := os.ReadDir(plan.Mount)
		fmt.Fprintf(os.Stderr, "rsbx: mount ready, %d entries, err=%v\n", len(ents), err)
		if sub, err := os.ReadDir(plan.Mount + "/usr/bin"); err == nil {
			fmt.Fprintf(os.Stderr, "rsbx: /usr/bin has %d entries\n", len(sub))
		} else {
			fmt.Fprintf(os.Stderr, "rsbx: /usr/bin: %v\n", err)
		}
		fmt.Fprintf(os.Stderr, "rsbx: bwrap argv = %q\n", plan.BwrapArgs(flag.Args()))
	}

	if *serve {
		// Keep the filesystem mounted without starting any program, so the
		// mount can be inspected on its own.
		select {}
	}
	argv := flag.Args()
	if len(argv) == 0 {
		entry := cfg.Local.Entry
		if entry == "" {
			entry = "/bin/sh"
		}
		argv = []string{entry}
	}
	// A signal ends this process without running any defer. Intercept the ones
	// that stop a build or a CI job, unmount, then die by the same signal so
	// the exit status still says how it ended.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		s := <-sigc
		stop()
		if sg, ok := s.(syscall.Signal); ok {
			syscall.Kill(os.Getpid(), sg)
		}
	}()

	code, err := plan.Run(argv)
	if err != nil {
		stop()
		fatal(err)
	}
	stop()
	os.Exit(code)
}

// fatal reports and exits. It is only safe once the mount is gone; callers that
// hold one unmount first.
func fatal(err error) {
	fmt.Fprintln(os.Stderr, "rsbx:", err)
	os.Exit(1)
}
