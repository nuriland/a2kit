//go:build windows

package capture

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// adapter is a network adapter, as pktmon lists it.
type adapter struct {
	id   int // its pktmon component
	mac  net.HardwareAddr
	name string
}

// pktmon runs pktmon.exe from System32 rather than the PATH, since an elevated process should not
// run whatever the PATH names.
func pktmon(args ...string) ([]byte, error) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		return nil, errors.New("SystemRoot is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, filepath.Join(root, "System32", "pktmon.exe"), args...).CombinedOutput()
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if msg := strings.TrimSpace(string(out)); err != nil && msg != "" {
		err = fmt.Errorf("%w: %s", err, msg)
	}
	return out, err
}

// Devices lists what OpenLive takes: "nics", every adapter at once, and then each adapter that
// pktmon lists with a MAC address, by its component ID. A VPN's tunnel has no MAC, and its
// component ID has changed between sessions, so "nics" is how to capture it.
func Devices() ([]Device, error) {
	as, err := adapters()
	if err != nil {
		return nil, err
	}
	devs := []Device{{Name: "nics", Description: "all network adapters"}}
	for _, a := range as {
		devs = append(devs, Device{Name: strconv.Itoa(a.id), Description: a.name + " (" + a.mac.String() + ")"})
	}
	return devs, nil
}

func adapters() ([]adapter, error) {
	out, err := pktmon("list")
	if err != nil {
		return nil, fmt.Errorf("capture: pktmon: listing adapters: %w", err)
	}
	return parseAdapters(out)
}

// parseAdapters reads the rows of pktmon list that give a component ID, a MAC address, and a name.
// Wi-Fi adapters are left out: pktmon logs them as 802.11 frames, which are not parsed.
func parseAdapters(text []byte) ([]adapter, error) {
	var as []adapter
	for line := range strings.Lines(string(text)) {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		id, err := strconv.Atoi(f[0])
		mac, macErr := net.ParseMAC(f[1])
		if err != nil || id < 1 || macErr != nil || len(mac) != 6 {
			continue
		}
		name := strings.Join(f[2:], " ")
		if lower := strings.ToLower(name); strings.Contains(lower, "wi-fi") || strings.Contains(lower, "wireless") {
			continue
		}
		as = append(as, adapter{id, mac, name})
	}
	if len(as) == 0 {
		return nil, errors.New("capture: pktmon: no network adapters listed")
	}
	slices.SortFunc(as, func(a, b adapter) int { return cmp.Compare(a.id, b.id) })
	return as, nil
}

// pktmonComponent resolves a device to a pktmon component: an ID, an adapter's name, or "nics" for
// all of them, which is 0 and what no name means.
func pktmonComponent(name string) (int, error) {
	if name == "" || strings.EqualFold(name, "nics") {
		return 0, nil
	}
	if id, err := strconv.Atoi(name); err == nil && id > 0 {
		return id, nil
	}
	as, err := adapters()
	if err != nil {
		return 0, err
	}
	return adapterNamed(as, name)
}

func adapterNamed(as []adapter, name string) (int, error) {
	i := slices.IndexFunc(as, func(a adapter) bool { return a.name == name })
	if i < 0 {
		return 0, fmt.Errorf("capture: pktmon: no device %q", name)
	}
	return as[i].id, nil
}
