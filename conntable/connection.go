package conntable

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang/snappy"
)

type PeerConnection struct {
	addr        string
	dialer      func(string) (net.Conn, *LocalPeerInfo, error)
	sendChan    chan *packet
	receiveChan chan *packet

	mu       sync.RWMutex
	PeerInfo LocalPeerInfo

	pool *sync.Pool

	lastActive             atomic.Value
	sendDropByteCounter    atomic.Int64
	receiveDropByteCounter atomic.Int64
	sendByteCounter        atomic.Int64
	receiveByteCounter     atomic.Int64
	isClosed               atomic.Bool

	maxQueueSize  int
	localPeerInfo *LocalPeerInfo
}

func NewConnection(addr string, dialer func(string) (net.Conn, *LocalPeerInfo, error), receiveChan chan *packet, pool *sync.Pool, maxQueueSize int, localPeerInfo *LocalPeerInfo) *PeerConnection {
	c := &PeerConnection{
		addr:          addr,
		dialer:        dialer,
		sendChan:      make(chan *packet, maxQueueSize),
		receiveChan:   receiveChan,
		pool:          pool,
		maxQueueSize:  maxQueueSize,
		localPeerInfo: localPeerInfo,
	}
	c.lastActive.Store(time.Now())
	c.sendByteCounter.Store(0)
	c.receiveByteCounter.Store(0)
	c.sendDropByteCounter.Store(0)
	c.receiveDropByteCounter.Store(0)
	c.isClosed.Store(false)
	return c
}

func (c *PeerConnection) Status() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	statusLine := fmt.Sprintf("Last active: %s\nSend queue size: %d\nTX bytes: %d, RX bytes: %d\nError TX bytes: %d, RX bytes: %d\n",
		c.lastActive.Load().(time.Time), len(c.sendChan), c.sendByteCounter.Load(), c.receiveByteCounter.Load(), c.sendDropByteCounter.Load(), c.receiveDropByteCounter.Load())
	configLine := fmt.Sprintf("Compression: %v\n", c.localPeerInfo.EnableCompression || c.PeerInfo.EnableCompression)
	return statusLine + configLine
}

func (t *PeerConnection) LastActive() time.Time {
	return t.lastActive.Load().(time.Time)
}

type writeflusher interface {
	Write([]byte) (int, error)
	Flush() error
}

func (c *PeerConnection) getPeerWriter(conn net.Conn) writeflusher {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.PeerInfo.EnableCompression || c.localPeerInfo.EnableCompression {
		return snappy.NewBufferedWriter(conn)
	}
	return bufio.NewWriterSize(conn, 16<<10)
}

func (c *PeerConnection) getPeerReader(conn net.Conn) io.Reader {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.PeerInfo.EnableCompression || c.localPeerInfo.EnableCompression {
		return snappy.NewReader(conn)
	}
	return bufio.NewReaderSize(conn, 16<<10)
}

func (c *PeerConnection) Close() {
	if c.isClosed.CompareAndSwap(false, true) {
		close(c.sendChan)
	}
}

func (c *PeerConnection) Send(p *packet) {
	if c.isClosed.Load() {
		return
	}
	pendingBytes := p.N
	select {
	case c.sendChan <- p:
		c.sendByteCounter.Add(int64(pendingBytes))
		c.lastActive.Store(time.Now())
	default:
		c.sendDropByteCounter.Add(int64(pendingBytes))
		c.pool.Put(p)
	}
}

func (c *PeerConnection) receiveLoop(conn net.Conn) {
	defer conn.Close()
	reader := c.getPeerReader(conn)
	for {
		packet := c.pool.Get().(*packet)
		packet.N = 0
		n, err := readBuffer(reader, packet.Data[offset:])
		if err != nil {
			return
		}
		packet.N = n + offset
		if c.isClosed.Load() {
			return
		}
		select {
		case c.receiveChan <- packet:
			c.receiveByteCounter.Add(int64(n))
			c.lastActive.Store(time.Now())
		default:
			c.receiveDropByteCounter.Add(int64(n))
			c.pool.Put(packet)
		}
	}
}

func batcher(packetChan chan *packet) ([]*packet, bool) {
	packets := make([]*packet, 1)
	var ok bool
	packets[0], ok = <-packetChan
	if !ok {
		return nil, ok
	}
	for {
		select {
		case npacket, ok := <-packetChan:
			if !ok {
				return nil, ok
			}
			packets = append(packets, npacket)
		default:
			return packets, true
		}
	}
}

func (c *PeerConnection) ChannelLoop(conn net.Conn) {
	var err error
	lastError := time.Time{}
	var writer writeflusher
	var peerInfo *LocalPeerInfo
	if conn == nil {
		err = fmt.Errorf("uninitialized")
		writer = nil
	} else {
		go c.receiveLoop(conn)
		writer = c.getPeerWriter(conn)
	}

	for {
		packets, ok := batcher(c.sendChan)
		if !ok {
			break
		}
		for _, packet := range packets {
			if err != nil {
				if time.Since(lastError) > time.Second {
					if conn != nil {
						conn.Close()
					}
					conn, peerInfo, err = c.dialer(c.addr)
					if err == nil {
						go c.receiveLoop(conn)
						c.mu.Lock()
						c.PeerInfo = *peerInfo
						c.mu.Unlock()
						writer = c.getPeerWriter(conn)
					} else {
						lastError = time.Now()
						conn = nil
						writer = nil
					}
				}
				c.pool.Put(packet)
				continue
			}
			if _, err = writeBuffer(writer, packet.Data[:packet.N], offset); err != nil {
				lastError = time.Now()
			} else {
				c.pool.Put(packet)
			}
		}
		if err == nil {
			writer.Flush()
		}
	}
	if conn != nil {
		conn.Close()
	}
}
