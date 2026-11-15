package sandbox

import "os"

// selfPath is this executable, for the launcher reexec.
func selfPath() string {
	exe, err := os.Executable()
	if err != nil {
		return os.Args[0]
	}
	return exe
}
