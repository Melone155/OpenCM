//go:build windows

package identity

import "golang.org/x/sys/windows"

// elevated reports whether the test runs with administrator rights (needed to take ownership).
func elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }
