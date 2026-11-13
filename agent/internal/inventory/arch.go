package inventory

import "runtime"

// goArchToMachine maps GOARCH to the conventional machine name.
func goArchToMachine() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "arm64"
	case "386":
		return "x86"
	}
	return runtime.GOARCH
}
