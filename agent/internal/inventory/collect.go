package inventory

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Collect gathers a full inventory. Individual collectors are best effort: a
// missing tool or permission leaves the corresponding section empty.
func Collect(ctx context.Context) (*Inventory, error) {
	inv := &Inventory{}
	if err := collectOS(ctx, inv); err != nil {
		return nil, err
	}
	inv.Network = collectNetwork()
	inv.CollectedAt = time.Now().UTC()
	sort.Slice(inv.Software, func(i, j int) bool {
		return strings.ToLower(inv.Software[i].Name) < strings.ToLower(inv.Software[j].Name)
	})
	inv.normalize()
	return inv, nil
}

// collectNetwork is OS-independent (Go's net package).
func collectNetwork() []NetIf {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []NetIf
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		n := NetIf{Name: i.Name, Up: i.Flags&net.FlagUp != 0, IPv4: []string{}, IPv6: []string{}}
		if len(i.HardwareAddr) > 0 {
			n.MAC = sp(i.HardwareAddr.String())
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if v4 := ipnet.IP.To4(); v4 != nil {
				n.IPv4 = append(n.IPv4, v4.String())
			} else if !ipnet.IP.IsLinkLocalUnicast() {
				n.IPv6 = append(n.IPv6, ipnet.IP.String())
			}
		}
		// skip virtual interfaces without any address (e.g. down tunnels)
		if n.MAC == nil && len(n.IPv4) == 0 && len(n.IPv6) == 0 {
			continue
		}
		out = append(out, n)
	}
	return out
}

// run executes a command with a timeout and returns stdout.
func run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		return string(out), fmt.Errorf("%s: %w", name, err)
	}
	return string(out), nil
}
