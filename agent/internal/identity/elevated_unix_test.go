//go:build !windows

package identity

// elevated: ownership checks on Unix do not need root in the tests.
func elevated() bool { return true }
