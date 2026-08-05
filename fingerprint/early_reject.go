package fingerprint

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"mango-waf/logger"
)

// EarlyRejectStats tracks statistics for raw TCP-level rejection
type EarlyRejectStats struct {
	TotalProcessed int64
	TotalRejected  int64
	LastError      string
}

var globalEarlyRejectStats EarlyRejectStats

// GetEarlyRejectStats returns current statistics
func GetEarlyRejectStats() (int64, int64) {
	return atomic.LoadInt64(&globalEarlyRejectStats.TotalProcessed),
		atomic.LoadInt64(&globalEarlyRejectStats.TotalRejected)
}

// SniffingListener wraps a net.Listener to perform early TLS fingerprint analysis without blocking Accept()
type SniffingListener struct {
	net.Listener
	Store         *FingerprintStore
	RejectLow     bool // Whether to reject low-trust fingerprints immediately
	IsUnderAttack func() bool
}

// NewSniffingListener creates a listener that performs early TLS sniffing lazily on worker goroutines
func NewSniffingListener(inner net.Listener, store *FingerprintStore, isUnderAttack func() bool) *SniffingListener {
	return &SniffingListener{
		Listener:      inner,
		Store:         store,
		RejectLow:     true,
		IsUnderAttack: isUnderAttack,
	}
}

// Accept implements net.Listener.Accept - RETURNS IMMEDIATELY to prevent blocking incoming connection queue
func (l *SniffingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	atomic.AddInt64(&globalEarlyRejectStats.TotalProcessed, 1)

	// Return Lazy Sniffing Connection wrapper to perform sniffing asynchronously on worker goroutine
	return &SniffingConn{
		Conn:     conn,
		listener: l,
	}, nil
}

// SniffingConn lazily performs TLS ClientHello sniffing on first Read() in its own worker goroutine
type SniffingConn struct {
	net.Conn
	listener *SniffingListener
	reader   *bufio.Reader
	sniffed  bool
	sniffErr error
}

func (c *SniffingConn) Read(b []byte) (n int, err error) {
	if !c.sniffed {
		c.sniffed = true
		c.performSniff()
	}
	if c.sniffErr != nil {
		return 0, c.sniffErr
	}
	if c.reader != nil {
		return c.reader.Read(b)
	}
	return c.Conn.Read(b)
}

func (c *SniffingConn) Close() error {
	return c.Conn.Close()
}

func (c *SniffingConn) performSniff() {
	// Set a 2-second read deadline for peeking initial bytes on worker goroutine
	c.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReaderSize(c.Conn, 2048)

	header, err := br.Peek(5)
	c.Conn.SetReadDeadline(time.Time{})

	if err != nil {
		if br.Buffered() > 0 {
			c.reader = br
		}
		return
	}

	c.reader = br

	// Check if TLS Handshake (0x16)
	if header[0] == 0x16 {
		recordLen := int(header[3])<<8 | int(header[4])
		if recordLen > 0 && recordLen < 16384 {
			peekSize := recordLen + 5
			if peekSize > 2048 {
				peekSize = 2048
			}

			raw, err := br.Peek(peekSize)
			if err == nil || err == io.EOF {
				fp, err := FullFingerprintFromRaw(raw)
				if err == nil {
					c.listener.Store.Store(c.Conn.RemoteAddr().String(), &ConnectionFingerprint{
						RemoteAddr: c.Conn.RemoteAddr().String(),
						JA3:        fp.JA3,
						JA4:        fp.JA4,
						Raw:        fp.ClientHello,
					})

					if c.listener.IsUnderAttack != nil && c.listener.IsUnderAttack() {
						db := GetDB()
						info, ok := db.LookupJA3(fp.JA3.Hash)
						if ok && info.TrustScore < 10 {
							atomic.AddInt64(&globalEarlyRejectStats.TotalRejected, 1)
							logger.Debug("TLS Early Reject triggered",
								"ip", c.Conn.RemoteAddr().String(),
								"ja3", fp.JA3.Hash,
								"tool", info.Name,
								"score", info.TrustScore,
							)
							c.Conn.Close()
							c.sniffErr = fmt.Errorf("early reject: known attack tool")
							return
						}
					}
				}
			}
		}
	}
}
