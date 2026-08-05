package cluster

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"mango-waf/config"
	"mango-waf/logger"

	"github.com/hashicorp/memberlist"
)

// BanMessage is the payload sent across the gossip network (IP Bans & Unbans)
type BanMessage struct {
	Action   string        `json:"action,omitempty"`
	IP       string        `json:"ip,omitempty"`
	Duration time.Duration `json:"duration,omitempty"`
	Source   string        `json:"source"`
	SentAt   int64         `json:"sent_at"`
}

// AlertSyncMessage is sent to silence other nodes when an alert is fired
type AlertSyncMessage struct {
	AlertType string `json:"alert_type"`
	Source    string `json:"source"`
	SentAt    int64  `json:"sent_at"`
}

// DomainAttackMessage is sent across mesh to aggregate cluster-wide DDoS metrics per domain
type DomainAttackMessage struct {
	Domain   string `json:"domain"`
	NodeName string `json:"node_name"`
	RPS      int64  `json:"rps"`
	Conns    int64  `json:"conns"`
	IsEnd    bool   `json:"is_end,omitempty"`
	SentAt   int64  `json:"sent_at"`
}

type PeerDomainStat struct {
	RPS    int64
	Conns  int64
	LastAt time.Time
}

// MeshNode represents a Mango Mesh edge node
type MeshNode struct {
	cfg             config.ClusterConfig
	list            *memberlist.Memberlist
	broadcasts      *memberlist.TransmitLimitedQueue
	banHandler      func(ip string, duration time.Duration)
	unbanHandler    func(ip string)
	alertHandler    func(alertType string)
	peerDomainStats sync.Map // domain_nodename -> PeerDomainStat
	mu              sync.RWMutex
}

var globalNode *MeshNode

// delegate handles memberlist events and messages
type delegate struct {
	node *MeshNode
}

func (d *delegate) NodeMeta(limit int) []byte {
	return []byte("mango-edge")
}

func (d *delegate) NotifyMsg(b []byte) {
	// Try DomainAttackMessage
	var domMsg DomainAttackMessage
	if err := json.Unmarshal(b, &domMsg); err == nil && domMsg.Domain != "" && domMsg.NodeName != "" {
		if domMsg.NodeName == d.node.cfg.NodeName {
			return
		}
		key := domMsg.Domain + "_" + domMsg.NodeName
		if domMsg.IsEnd {
			d.node.peerDomainStats.Delete(key)
		} else {
			d.node.peerDomainStats.Store(key, PeerDomainStat{
				RPS:    domMsg.RPS,
				Conns:  domMsg.Conns,
				LastAt: time.Now(),
			})
		}
		return
	}

	// Try BanMessage
	var banMsg BanMessage
	if err := json.Unmarshal(b, &banMsg); err == nil && (banMsg.IP != "" || banMsg.Action != "") {
		if banMsg.Source == d.node.cfg.NodeName {
			return
		}
		if time.Now().Unix()-banMsg.SentAt > 60 {
			return
		}
		if banMsg.Action == "unban" {
			logger.Debug("Received Unban Sync from Mesh", "ip", banMsg.IP, "source", banMsg.Source)
			if d.node.unbanHandler != nil {
				d.node.unbanHandler(banMsg.IP)
			}
			return
		}
		if banMsg.Action == "unban_all" {
			logger.Debug("Received UnbanAll Sync from Mesh", "source", banMsg.Source)
			if d.node.unbanHandler != nil {
				d.node.unbanHandler("all")
			}
			return
		}
		logger.Debug("Received Ban Sync from Mesh", "ip", banMsg.IP, "source", banMsg.Source)
		if d.node.banHandler != nil {
			d.node.banHandler(banMsg.IP, banMsg.Duration)
		}
		return
	}

	// Try AlertSyncMessage
	var alertMsg AlertSyncMessage
	if err := json.Unmarshal(b, &alertMsg); err == nil && alertMsg.AlertType != "" {
		if alertMsg.Source == d.node.cfg.NodeName {
			return
		}
		if time.Now().Unix()-alertMsg.SentAt > 10 { // Very fresh
			return
		}
		if d.node.alertHandler != nil {
			d.node.alertHandler(alertMsg.AlertType)
		}
		return
	}
}

func (d *delegate) GetBroadcasts(overhead, limit int) [][]byte {
	return d.node.broadcasts.GetBroadcasts(overhead, limit)
}

func (d *delegate) LocalState(join bool) []byte {
	return []byte{}
}

func (d *delegate) MergeRemoteState(buf []byte, join bool) {}

// broadcast implements memberlist.Broadcast
type banBroadcast struct {
	msg []byte
}

func (b *banBroadcast) Invalidates(other memberlist.Broadcast) bool {
	return false
}

func (b *banBroadcast) Message() []byte {
	return b.msg
}

func (b *banBroadcast) Finished() {}

// eventDelegate handles memberlist node join/leave/update events
type eventDelegate struct {
	node *MeshNode
}

func (e *eventDelegate) NotifyJoin(n *memberlist.Node) {
	logger.Info("Mesh node JOINED cluster", "name", n.Name, "addr", n.Addr.String(), "port", n.Port)
}

func (e *eventDelegate) NotifyLeave(n *memberlist.Node) {
	logger.Warn("Mesh node LEFT cluster", "name", n.Name, "addr", n.Addr.String())
}

func (e *eventDelegate) NotifyUpdate(n *memberlist.Node) {
	logger.Info("Mesh node UPDATED", "name", n.Name, "addr", n.Addr.String())
}

func autoDetectPublicIPv4() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()
		if localAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok && localAddr != nil && localAddr.IP != nil && !localAddr.IP.IsLoopback() {
			ipStr := localAddr.IP.String()
			if !strings.HasPrefix(ipStr, "172.17.") && !strings.HasPrefix(ipStr, "172.18.") {
				return ipStr
			}
		}
	}
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					ipStr := ip4.String()
					if !strings.HasPrefix(ipStr, "127.") && !strings.HasPrefix(ipStr, "172.17.") && !strings.HasPrefix(ipStr, "172.18.") {
						return ipStr
					}
				}
			}
		}
	}
	return ""
}

// InitMesh initializes the Zero-Dependency Gossip protocol
func InitMesh(cfg config.ClusterConfig, handleBan func(string, time.Duration), handleAlert func(string)) error {
	if !cfg.Enabled {
		return nil
	}

	mCfg := memberlist.DefaultWANConfig()
	advIP := cfg.AdvertiseIP
	if advIP == "" {
		advIP = autoDetectPublicIPv4()
	}
	if advIP != "" {
		mCfg.AdvertiseAddr = advIP
	}

	nodeName := cfg.NodeName
	if nodeName == "" {
		pubIP := getMyPublicIP()
		if pubIP != "" {
			nodeName = "mango-node-" + pubIP
		} else {
			host, _ := os.Hostname()
			if host != "" && host != "localhost" {
				nodeName = host
			} else if advIP != "" {
				nodeName = "mango-node-" + advIP
			} else {
				nodeName = "mango-node-primary"
			}
		}
	} else {
		pubIP := getMyPublicIP()
		if pubIP != "" && !strings.Contains(nodeName, pubIP) {
			nodeName = nodeName + "-" + pubIP
		}
	}
	mCfg.Name = nodeName
	mCfg.BindPort = cfg.BindPort
	if cfg.SecretKey != "" {
		key := []byte(cfg.SecretKey)
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			padded := make([]byte, 32)
			copy(padded, key)
			key = padded
		}
		mCfg.SecretKey = key
	}

	// Stability tuning for WAN gossip
	mCfg.GossipInterval = 500 * time.Millisecond
	mCfg.ProbeInterval = 3 * time.Second
	mCfg.ProbeTimeout = 2 * time.Second
	mCfg.SuspicionMult = 6 // Increase suspicion multiplier to tolerate transient network blips
	mCfg.RetransmitMult = 4

	n := &MeshNode{
		cfg:          cfg,
		banHandler:   handleBan,
		alertHandler: handleAlert,
	}

	d := &delegate{node: n}
	mCfg.Delegate = d

	// Event delegate for join/leave/update logging
	mCfg.Events = &eventDelegate{node: n}

	list, err := memberlist.Create(mCfg)
	if err != nil {
		return fmt.Errorf("failed to create memberlist: %w", err)
	}

	n.list = list
	n.broadcasts = &memberlist.TransmitLimitedQueue{
		NumNodes:       func() int { return list.NumMembers() },
		RetransmitMult: 4,
	}

	globalNode = n

	if len(cfg.JoinPeers) > 0 {
		num, err := list.Join(cfg.JoinPeers)
		if err != nil {
			logger.Warn("Initial join to mesh peers pending", "peers", cfg.JoinPeers, "error", err)
		} else {
			logger.Info("Initial join to mesh peers succeeded", "joined_nodes", num)
		}
		// Background auto-rejoin loop: aggressively maintain cluster connectivity
		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				currentMembers := list.NumMembers()
				expectedMembers := len(cfg.JoinPeers) + 1 // peers + self
				if currentMembers < expectedMembers {
					n, e := list.Join(cfg.JoinPeers)
					if e == nil && n > 0 {
						logger.Info("Mesh Cluster auto-reconnected to peers", "active_nodes", list.NumMembers(), "expected", expectedMembers)
					} else if e != nil {
						logger.Debug("Mesh auto-rejoin attempt failed", "error", e, "current_members", currentMembers)
					}
				}
			}
		}()
	}

	logger.Info("Mango Mesh Edge Node joined", "name", mCfg.Name, "members", list.NumMembers())
	return nil
}

// GetMesh returns the global mesh node
func GetMesh() *MeshNode {
	return globalNode
}

// BroadcastBan sends a ban command to all other Edge nodes in the mesh
func (n *MeshNode) BroadcastBan(ip string, duration time.Duration) {
	if n == nil || n.list == nil {
		return
	}

	msg := BanMessage{
		Action:   "ban",
		IP:       ip,
		Duration: duration,
		Source:   n.cfg.NodeName,
		SentAt:   time.Now().Unix(),
	}

	b, err := json.Marshal(msg)
	if err != nil {
		logger.Error("Failed to encode ban message", "error", err)
		return
	}

	n.broadcasts.QueueBroadcast(&banBroadcast{msg: b})
	logger.Debug("Broadcasted Ban to Mesh", "ip", ip)
}

// BroadcastUnban sends an unban command to all other Edge nodes in the mesh
func (n *MeshNode) BroadcastUnban(ip string) {
	if n == nil || n.list == nil {
		return
	}

	action := "unban"
	if ip == "all" {
		action = "unban_all"
	}

	msg := BanMessage{
		Action: action,
		IP:     ip,
		Source: n.cfg.NodeName,
		SentAt: time.Now().Unix(),
	}

	b, err := json.Marshal(msg)
	if err != nil {
		return
	}

	n.broadcasts.QueueBroadcast(&banBroadcast{msg: b})
	logger.Info("Broadcasted Unban to Mesh", "ip", ip, "action", action)
}

// SetBanHandler registers callback for remote bans
func (n *MeshNode) SetBanHandler(fn func(ip string, duration time.Duration)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.banHandler = fn
}

// SetUnbanHandler registers callback for remote unbans
func (n *MeshNode) SetUnbanHandler(fn func(ip string)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.unbanHandler = fn
}

// BroadcastAlert notifies other nodes that an alert was sent to prevent duplicate notifications
func (n *MeshNode) BroadcastAlert(alertType string) {
	if n == nil || n.list == nil {
		return
	}

	msg := AlertSyncMessage{
		AlertType: alertType,
		Source:    n.cfg.NodeName,
		SentAt:    time.Now().Unix(),
	}

	b, err := json.Marshal(msg)
	if err != nil {
		return
	}

	n.broadcasts.QueueBroadcast(&banBroadcast{msg: b}) // Can reuse the same broadcast struct
}

// BroadcastDomainMetric notifies other nodes of local domain RPS/conns metrics
func (n *MeshNode) BroadcastDomainMetric(domain string, rps, conns int64, isEnd bool) {
	if n == nil || n.list == nil {
		return
	}

	msg := DomainAttackMessage{
		Domain:   domain,
		NodeName: n.cfg.NodeName,
		RPS:      rps,
		Conns:    conns,
		IsEnd:    isEnd,
		SentAt:   time.Now().Unix(),
	}

	b, err := json.Marshal(msg)
	if err != nil {
		return
	}

	n.broadcasts.QueueBroadcast(&banBroadcast{msg: b})
}

// GetPeerDomainMetrics returns aggregated peer RPS and Conns for a domain
func (n *MeshNode) GetPeerDomainMetrics(domain string) (peerRPS, peerConns int64) {
	if n == nil {
		return 0, 0
	}
	n.peerDomainStats.Range(func(key, value interface{}) bool {
		kStr := key.(string)
		if len(kStr) > len(domain) && kStr[:len(domain)] == domain {
			stat := value.(PeerDomainStat)
			if time.Since(stat.LastAt) < 15*time.Second {
				peerRPS += stat.RPS
				peerConns += stat.Conns
			}
		}
		return true
	})
	return peerRPS, peerConns
}

// IsLeader checks if this node is the designated cluster alert coordinator (deterministic IP/Name leader selection)
func (n *MeshNode) IsLeader() bool {
	if n == nil || n.list == nil {
		return true // Standalone mode is always leader
	}
	local := n.list.LocalNode()
	if local == nil {
		return true
	}
	members := n.list.Members()
	if len(members) <= 1 {
		return true
	}
	myKey := fmt.Sprintf("%s_%s", local.Name, local.Addr.String())
	lowestKey := myKey
	for _, m := range members {
		key := fmt.Sprintf("%s_%s", m.Name, m.Addr.String())
		if key < lowestKey {
			lowestKey = key
		}
	}
	return myKey == lowestKey
}

// NumMembers returns the active number of nodes in the mesh
func (n *MeshNode) NumMembers() int {
	if n == nil || n.list == nil {
		return 0
	}
	return n.list.NumMembers()
}

// NodeInfo contains details about a single mesh node
type NodeInfo struct {
	Name string `json:"name"`
	Addr string `json:"addr"`
}

// GetMembers returns a list of connected node names and IPs
func (n *MeshNode) GetMembers() []NodeInfo {
	if n == nil || n.list == nil {
		return []NodeInfo{}
	}
	var members []NodeInfo
	for _, m := range n.list.Members() {
		members = append(members, NodeInfo{
			Name: m.Name,
			Addr: m.Addr.String(),
		})
	}
	return members
}

// Close gracefully leaves the mesh
func (n *MeshNode) Close() {
	if n != nil && n.list != nil {
		n.list.Leave(time.Second * 5)
		n.list.Shutdown()
	}
}

var publicIPOnce sync.Once
var myPublicIP = ""

func getMyPublicIP() string {
	publicIPOnce.Do(func() {
		urls := []string{
			"https://api.ipify.org",
			"https://ifconfig.me/ip",
			"https://icanhazip.com",
		}
		client := &http.Client{Timeout: 3 * time.Second}
		for _, url := range urls {
			resp, err := client.Get(url)
			if err == nil {
				defer resp.Body.Close()
				bytes, err := io.ReadAll(resp.Body)
				if err == nil {
					ip := strings.TrimSpace(string(bytes))
					if net.ParseIP(ip) != nil {
						myPublicIP = ip
						break
					}
				}
			}
		}
	})
	return myPublicIP
}
