package core

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"unsafe"

	"mango-waf/config"
	"mango-waf/logger"

	"golang.org/x/sys/unix"
)

// XDPManager provides a high-performance eBPF/XDP mapping interface for hardware-level dropping
type XDPManager struct {
	Enabled       bool
	MapName       string
	BPFToolBinary string
	mapFD         int // Native File Descriptor for zero-fork BPF map updates
	mapID         int // BPF Map ID for bpftool operations
}

func NewXDPManager(cfg *config.Config) *XDPManager {
	x := &XDPManager{
		MapName: "blacklist",
		mapFD:   -1,
		mapID:   -1,
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

	// 3. Try to open pinned map descriptor at configured or fallback paths
	pinPaths := []string{
		cfg.XDP.MapPinPath,
		"/sys/fs/bpf/mango_blacklist",
		"/sys/fs/bpf/blacklist",
		"/sys/fs/bpf/tc/globals/blacklist",
	}

	for _, pinPath := range pinPaths {
		if pinPath == "" {
			continue
		}
		fd, err := bpfObjGet(pinPath)
		if err == nil && fd > 0 {
			x.mapFD = fd
			x.Enabled = true
			logger.Info("XDP eBPF Native Map FD acquired (zero-fork mode)", "path", pinPath, "fd", fd)
			return x
		}
	}

	// 4. Fallback: discover bpftool for bootstrap and map discovery
	path, err := exec.LookPath("bpftool")
	if err != nil {
		path = "/usr/sbin/bpftool"
	}
	if _, err := os.Stat(path); err == nil {
		x.BPFToolBinary = path
		mapID := findBPFMapID(path, x.MapName)
		if mapID > 0 {
			x.mapID = mapID
			x.Enabled = true
			logger.Info("XDP eBPF Hardware Dropping Enabled via bpftool bootstrap", "map_id", mapID)
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

type BPFMapInfo struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	BytesKey   int    `json:"bytes_key"`
	BytesValue int    `json:"bytes_value"`
	MaxEntries int    `json:"max_entries"`
}

func findBPFMapID(bpftoolPath, mapName string) int {
	out, err := exec.Command(bpftoolPath, "-j", "map", "show").Output()
	if err != nil {
		return -1
	}
	var maps []BPFMapInfo
	if err := json.Unmarshal(out, &maps); err != nil {
		return -1
	}
	for _, m := range maps {
		if m.Name == mapName || (m.Type == "hash" && m.BytesKey == 4 && m.BytesValue == 8 && m.MaxEntries == 1000000) {
			return m.ID
		}
	}
	return -1
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

	// Check if already attached to NIC
	out, err := exec.Command("ip", "link", "show", "dev", nic).Output()
	if err == nil && strings.Contains(string(out), "xdp") {
		logger.Info("XDP filter already attached to network interface", "interface", nic)
		return
	}

	// Compile C source if mango_xdp.o missing and clang exists
	objFile := "xdp/mango_xdp.o"
	if _, err := os.Stat(objFile); os.IsNotExist(err) {
		if cfg.XDP.AutoCompile {
			if _, err := exec.LookPath("clang"); err == nil {
				archPath := fmt.Sprintf("/usr/include/%s-linux-gnu", getMachineArch())
				cmd := exec.Command("clang", "-O2", "-g", "-target", "bpf", "-c", "xdp/mango_xdp.c", "-o", objFile, "-I"+archPath, "-I/usr/include")
				if err := cmd.Run(); err == nil {
					logger.Info("Auto-compiled xdp/mango_xdp.c successfully")
				}
			}
		}
	}

	// Safety check for primary host physical interface eth0
	if (nic == "eth0" || nic == "ens3" || nic == "enp1s0") && os.Getenv("MANGO_XDP_HOST_ATTACH") != "true" {
		logger.Info("XDP eBPF map active in zero-fork mode. Auto-attach to host primary NIC ("+nic+") skipped to preserve SSH/Cloudflare connectivity. (Set MANGO_XDP_HOST_ATTACH=true or run xdp/setup_xdp.sh to attach).", "interface", nic)
		return
	}

	// Attach XDP object to NIC
	if _, err := os.Stat(objFile); err == nil {
		modeFlag := "xdpgeneric"
		if cfg.XDP.Mode == "drv" || cfg.XDP.Mode == "native" {
			modeFlag = "xdpdrv"
		}
		cmd := exec.Command("ip", "link", "set", "dev", nic, modeFlag, "obj", objFile, "sec", "xdp_mango")
		if err := cmd.Run(); err != nil {
			logger.Warn("Failed to auto-attach XDP to network interface", "interface", nic, "error", err)
		} else {
			logger.Info("Auto-attached XDP filter to network interface", "interface", nic, "mode", modeFlag)

			// Pin map to /sys/fs/bpf/mango_blacklist if not already pinned
			pinPath := cfg.XDP.MapPinPath
			if pinPath == "" {
				pinPath = "/sys/fs/bpf/mango_blacklist"
			}
			if _, err := os.Stat(pinPath); os.IsNotExist(err) {
				_ = exec.Command("bpftool", "map", "pin", "name", "blacklist", pinPath).Run()
			}
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

// BanIP pushes the banned IP address securely down to the NIC driver layer
func (x *XDPManager) BanIP(ipAddr string) error {
	if !x.Enabled {
		return nil
	}

	parsedIP := net.ParseIP(ipAddr)
	if parsedIP == nil {
		return fmt.Errorf("invalid ip")
	}

	ipv4 := parsedIP.To4()
	if ipv4 == nil {
		return fmt.Errorf("XDP currently supports IPv4 only") // Map key size is 4 bytes
	}

	// Native zero-fork syscall update if mapFD is open
	if x.mapFD > 0 {
		key := binary.BigEndian.Uint32(ipv4)
		var val uint64 = 0
		err := bpfMapUpdateElem(x.mapFD, unsafe.Pointer(&key), unsafe.Pointer(&val), 0)
		if err != nil {
			return fmt.Errorf("native bpf_map_update_elem failed: %w", err)
		}
		return nil
	}

	// Subprocess fallback by mapID or map name
	if x.BPFToolBinary != "" {
		hexIP := fmt.Sprintf("hex %02x %02x %02x %02x", ipv4[0], ipv4[1], ipv4[2], ipv4[3])
		hexVal := "hex 00 00 00 00 00 00 00 00"

		var args []string
		if x.mapID > 0 {
			args = []string{"map", "update", "id", strconv.Itoa(x.mapID), "key"}
		} else {
			args = []string{"map", "update", "name", x.MapName, "key"}
		}
		args = append(args, strings.Split(hexIP, " ")...)
		args = append(args, "value")
		args = append(args, strings.Split(hexVal, " ")...)

		cmd := exec.Command(x.BPFToolBinary, args...)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to update bpf map: %v", err)
		}
		return nil
	}

	return nil
}

// UnbanIP removes the IP address from the Hardware NIC drop list
func (x *XDPManager) UnbanIP(ipAddr string) error {
	if !x.Enabled {
		return nil
	}

	parsedIP := net.ParseIP(ipAddr)
	if parsedIP == nil || parsedIP.To4() == nil {
		return nil
	}
	ipv4 := parsedIP.To4()

	if x.mapFD > 0 {
		key := binary.BigEndian.Uint32(ipv4)
		err := bpfMapDeleteElem(x.mapFD, unsafe.Pointer(&key))
		if err != nil {
			return fmt.Errorf("native bpf_map_delete_elem failed: %w", err)
		}
		return nil
	}

	if x.BPFToolBinary != "" {
		hexIP := fmt.Sprintf("hex %02x %02x %02x %02x", ipv4[0], ipv4[1], ipv4[2], ipv4[3])
		var args []string
		if x.mapID > 0 {
			args = []string{"map", "delete", "id", strconv.Itoa(x.mapID), "key"}
		} else {
			args = []string{"map", "delete", "name", x.MapName, "key"}
		}
		args = append(args, strings.Split(hexIP, " ")...)

		cmd := exec.Command(x.BPFToolBinary, args...)
		return cmd.Run()
	}

	return nil
}

// Direct Linux BPF Syscall Helpers (zero-fork syscall operations)

type bpfAttrObjGet struct {
	pathname uint64
	bpfFd    uint32
	pad      uint32
}

type bpfAttrMapElem struct {
	mapFd uint32
	pad0  uint32
	key   uint64
	value uint64
	flags uint64
}

func bpfObjGet(path string) (int, error) {
	pathBytes, err := unix.BytePtrFromString(path)
	if err != nil {
		return -1, err
	}
	attr := bpfAttrObjGet{
		pathname: uint64(uintptr(unsafe.Pointer(pathBytes))),
	}
	r1, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(6), uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return -1, errno
	}
	return int(r1), nil
}

func bpfMapUpdateElem(fd int, key, value unsafe.Pointer, flags uint64) error {
	attr := bpfAttrMapElem{
		mapFd: uint32(fd),
		key:   uint64(uintptr(key)),
		value: uint64(uintptr(value)),
		flags: flags,
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(2), uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return errno
	}
	return nil
}

func bpfMapDeleteElem(fd int, key unsafe.Pointer) error {
	attr := bpfAttrMapElem{
		mapFd: uint32(fd),
		key:   uint64(uintptr(key)),
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(3), uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return errno
	}
	return nil
}

// GetStats returns the number of IPs currently in the hardware blacklist and total packets dropped
func (x *XDPManager) GetStats() (int64, int64) {
	if !x.Enabled {
		return 0, 0
	}

	if x.BPFToolBinary != "" {
		var cmd *exec.Cmd
		if x.mapID > 0 {
			cmd = exec.Command(x.BPFToolBinary, "-j", "map", "dump", "id", strconv.Itoa(x.mapID))
		} else {
			cmd = exec.Command(x.BPFToolBinary, "-j", "map", "dump", "name", x.MapName)
		}
		out, err := cmd.Output()
		if err != nil {
			return 0, 0
		}

		type BPFEntry struct {
			Key   []string `json:"key"`
			Value []string `json:"value"`
		}
		var entries []BPFEntry
		if err := json.Unmarshal(out, &entries); err != nil {
			return 0, 0
		}

		var totalDrops int64
		for _, e := range entries {
			if len(e.Value) == 8 {
				var val uint64
				for i := 0; i < 8; i++ {
					var b byte
					fmt.Sscanf(e.Value[i], "0x%x", &b)
					val |= uint64(b) << (i * 8)
				}
				totalDrops += int64(val)
			}
		}
		return int64(len(entries)), totalDrops
	}

	return 0, 0
}
