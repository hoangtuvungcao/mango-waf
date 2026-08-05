package core

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"sync"
	"sync/atomic"

	"mango-waf/config"
	"mango-waf/logger"

	"github.com/cilium/ebpf"
)

// XDPManager provides a high-performance eBPF/XDP mapping interface for hardware-level dropping
type XDPManager struct {
	Enabled       bool
	MapName       string
	bpfMap        *ebpf.Map
	lifetimeDrops int64
	lastObserved  map[uint32]uint64
	mu            sync.Mutex
}

func NewXDPManager(cfg *config.Config) *XDPManager {
	x := &XDPManager{
		MapName:      "blacklist",
		lastObserved: make(map[uint32]uint64),
	}

	if cfg == nil || !cfg.XDP.Enabled {
		logger.Info("XDP hardware dropping is disabled in configuration.")
		return x
	}

	// 1. Ensure /sys/fs/bpf is mounted
	if _, err := os.Stat("/sys/fs/bpf"); os.IsNotExist(err) {
		_ = os.MkdirAll("/sys/fs/bpf", 0755)
		_ = exec.Command("mount", "-t", "bpf", "bpffs", "/sys/fs/bpf").Run()
	}

	// 2. Try auto-attachment if enabled
	if cfg.XDP.AutoAttach {
		x.ensureAttached(cfg)
	}

	pinPath := cfg.XDP.MapPinPath
	if pinPath == "" {
		pinPath = "/sys/fs/bpf/mango_blacklist"
	}

	// 3. PRIORITIZE: Discover the active eBPF map ID created by attached XDP program
	var mapID ebpf.MapID
	var mapErr error
	for {
		mapID, mapErr = ebpf.MapGetNextID(mapID)
		if mapErr != nil {
			break
		}
		m, err := ebpf.NewMapFromID(mapID)
		if err != nil {
			continue
		}
		info, err := m.Info()
		if err == nil && info.Name == "blacklist" && info.Type == ebpf.Hash {
			x.bpfMap = m
			x.Enabled = true

			// Force unpin stale path and re-pin to active map ID
			_ = os.Remove(pinPath)
			if err := m.Pin(pinPath); err == nil {
				logger.Info("Discovered active XDP map ID and re-pinned it successfully", "id", mapID, "path", pinPath)
			} else {
				logger.Info("Discovered active XDP map ID", "id", mapID)
			}
			return x
		}
		m.Close()
	}

	// 4. Fallback: Try to open pinned map descriptor if kernel scan did not yield map
	pinPaths := []string{
		pinPath,
		"/sys/fs/bpf/mango_blacklist",
		"/sys/fs/bpf/blacklist",
		"/sys/fs/bpf/tc/globals/blacklist",
	}
	for _, p := range pinPaths {
		if p == "" {
			continue
		}
		m, err := ebpf.LoadPinnedMap(p, nil)
		if err == nil && m != nil {
			x.bpfMap = m
			x.Enabled = true
			logger.Info("XDP eBPF Native Map loaded via pinned file", "path", p)
			return x
		}
	}

	// 5. Create standalone BPF hash map if not found anywhere
	if _, err := os.Stat("/sys/fs/bpf"); err == nil {
		spec := &ebpf.MapSpec{
			Name:       "blacklist",
			Type:       ebpf.Hash,
			KeySize:    4,
			ValueSize:  8,
			MaxEntries: 1000000,
		}
		m, err := ebpf.NewMap(spec)
		if err == nil && m != nil {
			x.bpfMap = m
			x.Enabled = true

			_ = os.Remove(pinPath)
			if err := m.Pin(pinPath); err == nil {
				logger.Info("XDP eBPF blacklist map created and pinned", "path", pinPath)
			}
			return x
		}
	}

	// Check root privilege for informative warning
	if currentUser, err := user.Current(); err == nil && currentUser.Uid != "0" {
		logger.Warn("XDP requires root / CAP_BPF privileges and attached NIC filter. Run xdp/setup_xdp.sh or set auto_attach: true.")
	} else {
		logger.Warn("XDP map 'blacklist' not found. Run xdp/setup_xdp.sh or ensure xdp_mango runs on NIC.")
	}
	return x
}

func (x *XDPManager) ensureAttached(cfg *config.Config) {
	nic := cfg.XDP.Interface
	if nic == "" {
		nic = detectDefaultInterface()
	}
	if nic == "" {
		return
	}

	if !cfg.XDP.AutoAttach {
		return
	}

	objFile := "xdp/mango_xdp.o"
	if cfg.XDP.AutoCompile {
		if _, err := exec.LookPath("clang"); err == nil {
			archPath := fmt.Sprintf("/usr/include/%s-linux-gnu", getMachineArch())
			cmd := exec.Command("clang", "-O2", "-g", "-target", "bpf", "-c", "xdp/mango_xdp.c", "-o", objFile, "-I"+archPath, "-I/usr/include")
			if err := cmd.Run(); err == nil {
				logger.Info("Auto-compiled xdp/mango_xdp.c to fresh BPF object successfully")
			} else {
				logger.Warn("Clang compilation of xdp/mango_xdp.c failed", "error", err)
			}
		}
	}

	if (nic == "eth0" || nic == "ens3" || nic == "enp1s0") && os.Getenv("MANGO_XDP_HOST_ATTACH") != "true" {
		logger.Info("XDP eBPF map active. Auto-attach to host primary NIC (" + nic + ") skipped to preserve SSH. Set MANGO_XDP_HOST_ATTACH=true to override.")
		return
	}

	if _, err := os.Stat(objFile); err == nil {
		modeFlag := "xdpgeneric"
		if cfg.XDP.Mode == "drv" || cfg.XDP.Mode == "native" {
			modeFlag = "xdpdrv"
		}

		// Detach old XDP filter to guarantee fresh bytecode loading
		_ = exec.Command("ip", "link", "set", "dev", nic, "xdp", "off").Run()
		_ = exec.Command("ip", "link", "set", "dev", nic, "xdpgeneric", "off").Run()

		cmd := exec.Command("ip", "link", "set", "dev", nic, modeFlag, "obj", objFile, "sec", "xdp_mango")
		if err := cmd.Run(); err != nil {
			logger.Warn("Failed to auto-attach XDP to network interface", "interface", nic, "error", err)
		} else {
			logger.Info("Freshly attached XDP filter to network interface", "interface", nic, "mode", modeFlag)
		}
	}
}

func detectDefaultInterface() string {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "eth0"
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return "eth0"
}

func getMachineArch() string {
	out, err := exec.Command("uname", "-m").Output()
	if err != nil {
		return "x86_64"
	}
	return strings.TrimSpace(string(out))
}

// BanIP pushes the banned IP address securely down to the NIC driver layer natively via cilium/ebpf
func (x *XDPManager) BanIP(ipAddr string) error {
	if !x.Enabled || x.bpfMap == nil {
		return nil
	}

	parsedIP := net.ParseIP(ipAddr)
	if parsedIP == nil || parsedIP.To4() == nil {
		return fmt.Errorf("invalid IPv4")
	}
	ipv4 := parsedIP.To4()

	// LittleEndian.Uint32 produces the correct byte layout in x86 memory
	// that matches ip->saddr as read by the XDP kernel program on LE CPUs.
	key := binary.LittleEndian.Uint32(ipv4)
	var val uint64 = 0

	// Use UpdateNoExist: only insert if not already present.
	// This preserves the existing XDP kernel drop counter that gets
	// atomically incremented by __sync_fetch_and_add() in the C BPF program.
	// If we used UpdateAny, we'd reset the counter to 0 on every ban refresh.
	err := x.bpfMap.Update(&key, &val, ebpf.UpdateNoExist)
	if err != nil {
		// Already banned (key exists) - do NOT reset the drop counter
		if errors.Is(err, ebpf.ErrKeyExist) || strings.Contains(strings.ToLower(err.Error()), "exist") {
			return nil
		}
		return fmt.Errorf("cilium/ebpf map update failed: %w", err)
	}
	return nil
}

// UnbanIP removes the IP address from the Hardware NIC drop list natively
func (x *XDPManager) UnbanIP(ipAddr string) error {
	if !x.Enabled || x.bpfMap == nil {
		return nil
	}

	parsedIP := net.ParseIP(ipAddr)
	if parsedIP == nil || parsedIP.To4() == nil {
		return nil
	}
	ipv4 := parsedIP.To4()

	key := binary.LittleEndian.Uint32(ipv4)
	err := x.bpfMap.Delete(&key)
	if err != nil && !strings.Contains(err.Error(), "key does not exist") {
		return fmt.Errorf("cilium/ebpf map delete failed: %w", err)
	}
	return nil
}

// GetStats returns the number of IPs currently in the hardware blacklist and total packets dropped natively
func (x *XDPManager) GetStats() (int64, int64) {
	if !x.Enabled || x.bpfMap == nil {
		return 0, atomic.LoadInt64(&x.lifetimeDrops)
	}

	var count int64
	var currentActiveDrops int64

	x.mu.Lock()
	if x.lastObserved == nil {
		x.lastObserved = make(map[uint32]uint64)
	}

	iter := x.bpfMap.Iterate()
	var key uint32
	var value uint64
	for iter.Next(&key, &value) {
		count++
		currentActiveDrops += int64(value)

		oldVal := x.lastObserved[key]
		if value > oldVal {
			diff := int64(value - oldVal)
			atomic.AddInt64(&x.lifetimeDrops, diff)
			x.lastObserved[key] = value
		}
	}

	if err := iter.Err(); err != nil {
		logger.Warn("Failed to iterate BPF map", "error", err)
	}
	x.mu.Unlock()

	lifetime := atomic.LoadInt64(&x.lifetimeDrops)
	if lifetime > currentActiveDrops {
		return count, lifetime
	}
	return count, currentActiveDrops
}
