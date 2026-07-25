package core

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"unsafe"

	"mango-waf/logger"

	"golang.org/x/sys/unix"
)

// XDPManager provides a high-performance eBPF/XDP mapping interface for hardware-level dropping
type XDPManager struct {
	Enabled       bool
	MapName       string
	BPFToolBinary string
	mapFD         int // Native File Descriptor for zero-fork BPF map updates
}

func NewXDPManager() *XDPManager {
	x := &XDPManager{
		MapName: "blacklist",
		mapFD:   -1,
	}

	// 1. Must be root to mess with eBPF maps
	currentUser, err := user.Current()
	if err != nil || currentUser.Uid != "0" {
		logger.Warn("XDP requires root privileges. XDP hardware dropping disabled.")
		return x
	}

	// 2. Try to open pinned map descriptor at /sys/fs/bpf/mango_blacklist or /sys/fs/bpf/blacklist
	pinPaths := []string{
		"/sys/fs/bpf/mango_blacklist",
		"/sys/fs/bpf/blacklist",
		"/sys/fs/bpf/tc/globals/blacklist",
	}

	for _, pinPath := range pinPaths {
		fd, err := bpfObjGet(pinPath)
		if err == nil && fd > 0 {
			x.mapFD = fd
			x.Enabled = true
			logger.Info("XDP eBPF Native Map FD acquired (zero-fork mode)", "path", pinPath, "fd", fd)
			return x
		}
	}

	// 3. Fallback: discover bpftool for bootstrap
	path, err := exec.LookPath("bpftool")
	if err != nil {
		path = "/usr/sbin/bpftool" // fallback
	}
	if _, err := os.Stat(path); err == nil {
		x.BPFToolBinary = path
		cmd := exec.Command(x.BPFToolBinary, "map", "show", "name", x.MapName)
		if err := cmd.Run(); err == nil {
			x.Enabled = true
			logger.Info("XDP eBPF Hardware Dropping Enabled via bpftool bootstrap.")
			return x
		}
	}

	logger.Warn("XDP map 'blacklist' not found. Ensure xdp_mango runs successfully on NIC.")
	return x
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

	// Subprocess fallback
	if x.BPFToolBinary != "" {
		hexIP := fmt.Sprintf("hex %02x %02x %02x %02x", ipv4[0], ipv4[1], ipv4[2], ipv4[3])
		hexVal := "hex 00 00 00 00 00 00 00 00"

		args := []string{"map", "update", "name", x.MapName, "key"}
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
		args := []string{"map", "delete", "name", x.MapName, "key"}
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
		cmd := exec.Command(x.BPFToolBinary, "-j", "map", "dump", "name", x.MapName)
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
