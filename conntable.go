package main

import (
	"bufio"
	"encoding/gob"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/trace"
	"golang.zx2c4.com/wireguard/tun"
)

type PeerConnection struct {
	dialer      func() (net.Conn, error)
	sendChan    chan *Packet
	receiveChan chan *Packet

	mu         sync.RWMutex
	lastActive time.Time
	isClosed   bool
	pool       *sync.Pool

	maxQueueSize int
	tracker      trace.EventLog
}

func NewConnection(addr string, dialer func() (net.Conn, error), receiveChan chan *Packet, pool *sync.Pool, maxQueueSize int) *PeerConnection {
	return &PeerConnection{
		dialer:       dialer,
		sendChan:     make(chan *Packet, maxQueueSize),
		receiveChan:  receiveChan,
		lastActive:   time.Now(),
		isClosed:     false,
		pool:         pool,
		maxQueueSize: maxQueueSize,
		tracker:      trace.NewEventLog("Peer", "Connection to "+addr),
	}
}

func (c *PeerConnection) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.isClosed {
		return
	}
	close(c.sendChan)
	c.tracker.Finish()
	c.isClosed = true
}

func (c *PeerConnection) Send(p *Packet) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.isClosed {
		return
	}
	select {
	case c.sendChan <- p:
	default:
		c.tracker.Errorf("Send loop is full: some packets dropped")
	}
}

func (c *PeerConnection) receiveLoop(conn net.Conn) {
	c.tracker.Printf("Starting receiving loop for %v", conn.RemoteAddr())
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		packet := c.pool.Get().(*Packet)
		packet.N = 0
		n, err := readBuffer(reader, packet.Data[offset:])
		if err != nil {
			c.tracker.Errorf("Closed peer connection %v: %v", conn.RemoteAddr(), err)
			return
		}
		packet.N = n + offset
		c.mu.RLock()
		if c.isClosed {
			c.mu.RUnlock()
			return
		}
		select {
		case c.receiveChan <- packet:
		default:
			c.tracker.Errorf("Receive loop is full: some packets dropped")
		}
		c.mu.RUnlock()
	}
}

func (c *PeerConnection) ChannelLoop(conn net.Conn) {
	var err error
	lastError := time.Time{}
	if conn == nil {
		err = fmt.Errorf("uninitialized")
	} else {
		go c.receiveLoop(conn)
	}
	c.tracker.Printf("Starting channel loop")
	for packet := range c.sendChan {
		if err != nil {
			if time.Since(lastError) > time.Second {
				if conn != nil {
					conn.Close()
				}
				c.tracker.Printf("Initializing connection")
				conn, err = c.dialer()
				if err == nil {
					go c.receiveLoop(conn)
				} else {
					c.tracker.Errorf("Initializing connection failed: %v", err)
					lastError = time.Now()
				}
			}
			continue
		}
		if _, err = writeBuffer(conn, packet.Data[:packet.N], offset); err != nil {
			lastError = time.Now()
		}
		c.pool.Put(packet)
	}
	if conn != nil {
		conn.Close()
	}
}

type PeerTable struct {
	mu       sync.Mutex
	isClosed bool
	table    map[string]*PeerConnection

	device      tun.Device
	listener    net.Listener
	receiveChan chan *Packet
	pool        sync.Pool

	mtu          int
	localNet     netip.Prefix
	localAddr    string
	dialer       func(string) (net.Conn, error)
	maxQueueSize int
}

func NewPeerTable(mtu int, device tun.Device, listener net.Listener, localNet netip.Prefix, localAddr string, dialer func(string) (net.Conn, error), maxQueueSize int) *PeerTable {
	return &PeerTable{
		isClosed:    false,
		table:       map[string]*PeerConnection{},
		device:      device,
		listener:    listener,
		receiveChan: make(chan *Packet, maxQueueSize),
		pool: sync.Pool{New: func() any {
			return &Packet{Data: make([]byte, mtu+offset), N: 0, Capacity: mtu + offset}
		}},
		mtu:          mtu,
		localNet:     localNet,
		localAddr:    localAddr,
		dialer:       dialer,
		maxQueueSize: maxQueueSize,
	}
}

func (t *PeerTable) dialToPeer(s string) (net.Conn, error) {
	tracker := trace.New("corenet.Dial", "New connection to "+s)
	defer tracker.Finish()
	conn, err := t.dialer(s)
	if err != nil {
		tracker.LazyPrintf(err.Error())
		tracker.SetError()
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := gob.NewEncoder(conn).Encode(PeerHello{FromAddr: t.localAddr, ToAddr: s}); err != nil {
		tracker.LazyPrintf("Handshake failed on request")
		tracker.LazyPrintf(err.Error())
		tracker.SetError()
		conn.Close()
		return nil, err
	}
	resp := PeerResponse{}
	if err := gob.NewDecoder(conn).Decode(&resp); err != nil {
		tracker.LazyPrintf("Handshake failed on response")
		tracker.LazyPrintf(err.Error())
		tracker.SetError()
		conn.Close()
		return nil, err
	}
	if !resp.Success {
		tracker.LazyPrintf("Handshake failed by remote peer: %s", resp.Reason)
		tracker.SetError()
		conn.Close()
		return nil, fmt.Errorf("app error: %s", resp.Reason)
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

func (t *PeerTable) serveReadDeviceLoop() {
	for {
		packet := t.pool.Get().(*Packet)
		n, err := t.device.Read(packet.Data, offset)
		if err != nil {
			log.Printf("Tunnel read loop closed: %v, exiting", err)
			t.Close()
			return
		}
		if n == 0 {
			continue
		}
		packet.N = n + offset
		dst := getDstKeyFromPacket(packet.Data[offset : n+offset])
		dstIP, err := netip.ParseAddr(dst)
		if err != nil {
			continue
		}
		if t.localNet.Contains(dstIP) {
			t.mu.Lock()
			peerConn, exists := t.table[dst]
			if !exists {
				dstDialer := func() (net.Conn, error) { return t.dialToPeer(dst) }
				peerConn = NewConnection(dst, dstDialer, t.receiveChan, &t.pool, t.maxQueueSize)
				go peerConn.ChannelLoop(nil)
				t.table[dst] = peerConn
			}
			t.mu.Unlock()
			peerConn.Send(packet)
		}
	}
}

func (t *PeerTable) serveWriteDeviceLoop() {
	for buffer := range t.receiveChan {
		t.device.Write(buffer.Data[:buffer.N], offset)
		t.pool.Put(buffer)
	}
	log.Printf("Tunnel write loop closed")
	t.Close()
}

func (t *PeerTable) servePeerIncomingConnnectionLoop() {
	for {
		peerConn, err := t.listener.Accept()
		if err != nil {
			log.Printf("Tunnel channel closed: %v, exiting", err)
			t.Close()
			return
		}
		go func(peerConn net.Conn) {
			peerHello := PeerHello{}
			if err := gob.NewDecoder(peerConn).Decode(&peerHello); err != nil {
				return
			}
			if peerHello.ToAddr != t.localAddr {
				gob.NewEncoder(peerConn).Encode(PeerResponse{Success: false, Reason: fmt.Sprintf("expect local addr: %s, got %s", t.localAddr, peerHello.ToAddr)})
				return
			}
			if err := gob.NewEncoder(peerConn).Encode(PeerResponse{Success: true}); err != nil {
				return
			}
			t.mu.Lock()
			defer t.mu.Unlock()
			peerCh, exists := t.table[peerHello.FromAddr]
			if !exists {
				dstDialer := func() (net.Conn, error) { return t.dialToPeer(peerHello.FromAddr) }
				peerCh = NewConnection(peerHello.FromAddr, dstDialer, t.receiveChan, &t.pool, t.maxQueueSize)
				t.table[peerHello.FromAddr] = peerCh
				go peerCh.ChannelLoop(peerConn)
			} else {
				go peerCh.receiveLoop(peerConn)
			}
		}(peerConn)
	}
}

func (t *PeerTable) Serve() {
	wg := sync.WaitGroup{}
	wg.Add(3)
	go func() {
		t.servePeerIncomingConnnectionLoop()
		wg.Done()
	}()
	go func() {
		t.serveReadDeviceLoop()
		wg.Done()
	}()
	go func() {
		t.serveWriteDeviceLoop()
		wg.Done()
	}()
	wg.Wait()
}

func (t *PeerTable) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.isClosed {
		return
	}
	t.isClosed = true

	for _, val := range t.table {
		val.Close()
	}
	t.listener.Close()
	t.device.Close()
	close(t.receiveChan)
}
