package cluster

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"mango-waf/config"
	"mango-waf/logger"

	"github.com/hashicorp/memberlist"
)

// BanMessage is the payload sent across the gossip network (IP Bans)
type BanMessage struct {
	IP       string        `json:"ip"`
	Duration time.Duration `json:"duration"`
	Source   string        `json:"source"`
	SentAt   int64         `json:"sent_at"`
}

// AlertSyncMessage is sent to silence other nodes when an alert is fired
type AlertSyncMessage struct {
	AlertType string `json:"alert_type"`
	Source    string `json:"source"`
	SentAt    int64  `json:"sent_at"`
}

// MeshNode represents a Mango Mesh edge node
type MeshNode struct {
	cfg          config.ClusterConfig
	list         *memberlist.Memberlist
	broadcasts   *memberlist.TransmitLimitedQueue
	banHandler   func(ip string, duration time.Duration)
	alertHandler func(alertType string)
	mu           sync.RWMutex
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
	// Try BanMessage first
	var banMsg BanMessage
	if err := json.Unmarshal(b, &banMsg); err == nil && banMsg.IP != "" {
		if banMsg.Source == d.node.cfg.NodeName {
			return
		}
		if time.Now().Unix()-banMsg.SentAt > 60 {
			return
		}
		logger.Info("Received Ban Sync from Mesh", "ip", banMsg.IP, "source", banMsg.Source)
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

// InitMesh initializes the Zero-Dependency Gossip protocol
func InitMesh(cfg config.ClusterConfig, handleBan func(string, time.Duration), handleAlert func(string)) error {
	if !cfg.Enabled {
		return nil
	}

	mCfg := memberlist.DefaultWANConfig()
	if cfg.NodeName != "" {
		mCfg.Name = cfg.NodeName
	}
	mCfg.BindPort = cfg.BindPort
	if cfg.AdvertiseIP != "" {
		mCfg.AdvertiseAddr = cfg.AdvertiseIP
	}
	if cfg.SecretKey != "" {
		key := []byte(cfg.SecretKey)
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			padded := make([]byte, 32)
			copy(padded, key)
			key = padded
		}
		mCfg.SecretKey = key
	}

	n := &MeshNode{
		cfg:          cfg,
		banHandler:   handleBan,
		alertHandler: handleAlert,
	}

	d := &delegate{node: n}
	mCfg.Delegate = d

	// Optional: disable memberlist internal logging
	// mCfg.Logger = log.New(io.Discard, "", 0)

	list, err := memberlist.Create(mCfg)
	if err != nil {
		return fmt.Errorf("failed to create memberlist: %w", err)
	}

	n.list = list
	n.broadcasts = &memberlist.TransmitLimitedQueue{
		NumNodes:       func() int { return list.NumMembers() },
		RetransmitMult: 3,
	}

	globalNode = n

	if len(cfg.JoinPeers) > 0 {
		_, err := list.Join(cfg.JoinPeers)
		if err != nil {
			logger.Warn("Failed to join all mesh peers", "error", err)
		}
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
	logger.Info("Broadcasted Ban to Mesh", "ip", ip)
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
