package sandbox

import "rsbx/internal/config"

// testCfg is the smallest configuration the argument builder needs.
func testCfg() *config.Config {
	cfg := config.Default()
	cfg.Daemon.Transport = "unix"
	cfg.Daemon.Socket = "/run/rsbx/daemon.sock"
	return cfg
}
