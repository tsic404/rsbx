package sandbox

import "rsbx/internal/config"

// testCfg is the smallest configuration the tests below need. The daemon
// socket points at a path nothing binds: the broker owns the transport now.
func testCfg() *config.Config {
	cfg := config.Default()
	cfg.Daemon.Transport = "unix"
	cfg.Daemon.Socket = "/run/rsbx/daemon.sock"
	return cfg
}
