package conntable

import (
	"bufio"
	"fmt"
	"net"
	"sync"
	"time"
)

type PeerConnection struct {
	addr        string
	dialer      func(string) (net.Conn, error)
	sendChan    chan *packet
	receiveChan chan *packet

	mu                     sync.RWMutex
	lastActive             time.Time
	isClosed               bool
	pool                   *sync.Pool
	sendDropByteCounter    int64
	receiveDropByteCounter int64
	sendByteCounter        int64
	receiveByteCounter     int64

	maxQueueSize int
}

func NewConnection(addr string, dialer func(string) (net.Conn, error), receiveChan chan *packet, pool *sync.Pool, maxQueueSize int) *PeerConnection {
	return &PeerConnection{
		addr:                   addr,
		dialer:                 dialer,
		sendChan:               make(chan *packet, maxQueueSize),
		receiveChan:            receiveChan,
		lastActive:             time.Now(),
		isClosed:               false,
		pool:                   pool,
		maxQueueSize:           maxQueueSize,
		sendDropByteCounter:    0,
		receiveDropByteCounter: 0,
		sendByteCounter:        0,
		receiveByteCounter:     0,
	}
}

func (c *PeerConnection) Status() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return fmt.Sprintf("Last active: %s\nSend queue size: %d\nTX bytes: %d, RX bytes: %d\nError TX bytes: %d, RX bytes: %d\n",
		c.lastActive, len(c.sendChan), c.sendByteCounter, c.receiveByteCounter, c.sendDropByteCounter, c.receiveDropByteCounter)
}

func (t *PeerConnection) LastActive() time.Time {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.lastActive
}

func (c *PeerConnection) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.isClosed {
		return
	}
	close(c.sendChan)
	c.isClosed = true
}

func (c *PeerConnection) Send(p *packet) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.isClosed {
		return
	}
	pendingBytes := p.N
	select {
	case c.sendChan <- p:
		c.sendByteCounter += int64(pendingBytes)
		c.lastActive = time.Now()
	default:
		c.sendDropByteCounter += int64(pendingBytes)
		c.pool.Put(p)
	}
}

func (c *PeerConnection) receiveLoop(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReaderSize(conn, 16<<10)
	for {
		packet := c.pool.Get().(*packet)
		packet.N = 0
		n, err := readBuffer(reader, packet.Data[offset:])
		if err != nil {
			return
		}
		packet.N = n + offset
		c.mu.Lock()
		if c.isClosed {
			c.mu.Unlock()
			return
		}
		select {
		case c.receiveChan <- packet:
			c.receiveByteCounter += int64(n)
			c.lastActive = time.Now()
		default:
			c.receiveDropByteCounter += int64(n)
			c.pool.Put(packet)
		}
		c.mu.Unlock()
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
	var writer *bufio.Writer
	if conn == nil {
		err = fmt.Errorf("uninitialized")
		writer = nil
	} else {
		go c.receiveLoop(conn)
		writer = bufio.NewWriterSize(conn, 16<<10)
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
					conn, err = c.dialer(c.addr)
					if err == nil {
						go c.receiveLoop(conn)
						writer = bufio.NewWriterSize(conn, 16<<10)
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
