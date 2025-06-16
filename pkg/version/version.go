package version

import (
	"fmt"
	"runtime"
)

var (
	// Version will be set at build time
	Version = "dev"
	// BuildTime will be set at build time
	BuildTime = "unknown"
	// GitCommit will be set at build time
	GitCommit = "unknown"
)

// GetVersion returns formatted version information
func GetVersion() string {
	return fmt.Sprintf(`ks version %s
Build time: %s
Git commit: %s
Go version: %s
OS/Arch: %s/%s`,
		Version,
		BuildTime,
		GitCommit,
		runtime.Version(),
		runtime.GOOS,
		runtime.GOARCH,
	)
}

// GetShortVersion returns just the version string
func GetShortVersion() string {
	return Version
}
