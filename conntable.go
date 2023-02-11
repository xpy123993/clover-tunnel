package main

import (
	"bufio"
	"encoding/gob"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/xpy123993/corenet"
	"golang.zx2c4.com/wireguard/tun"
)

const offset = 4

type PeerHello struct {
	FromAddr string `json:"from-addr"`
	ToAddr   string `json:"to-addr"`
}

type PeerResponse struct {
	Success bool   `json:"success"`
	Reason  string `json:"reason"`
}

type Packet struct {
	Data     []byte
	N        int
	Capacity int
}

type PeerConnection struct {
	addr        string
	dialer      func(string) (net.Conn, error)
	sendChan    chan *Packet
	receiveChan chan *Packet

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

func NewConnection(addr string, dialer func(string) (net.Conn, error), receiveChan chan *Packet, pool *sync.Pool, maxQueueSize int) *PeerConnection {
	return &PeerConnection{
		addr:                   addr,
		dialer:                 dialer,
		sendChan:               make(chan *Packet, maxQueueSize),
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
func (c *PeerConnection) RefreshLastActive() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastActive = time.Now()
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

func (c *PeerConnection) Send(p *Packet) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.isClosed {
		return
	}
	pendingBytes := p.N
	select {
	case c.sendChan <- p:
		c.sendByteCounter += int64(pendingBytes)
	default:
		c.sendDropByteCounter += int64(pendingBytes)
	}
}

func (c *PeerConnection) receiveLoop(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		packet := c.pool.Get().(*Packet)
		packet.N = 0
		n, err := readBuffer(reader, packet.Data[offset:])
		if err != nil {
			return
		}
		c.RefreshLastActive()
		packet.N = n + offset
		c.mu.Lock()
		if c.isClosed {
			c.mu.Unlock()
			return
		}
		select {
		case c.receiveChan <- packet:
			c.receiveByteCounter += int64(n)
		default:
			c.receiveDropByteCounter += int64(n)
		}
		c.mu.Unlock()
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
	for packet := range c.sendChan {
		if err != nil {
			if time.Since(lastError) > time.Second {
				if conn != nil {
					conn.Close()
				}
				conn, err = c.dialer(c.addr)
				if err == nil {
					go c.receiveLoop(conn)
				} else {
					lastError = time.Now()
				}
			}
			continue
		}
		if _, err = writeBuffer(conn, packet.Data[:packet.N], offset); err != nil {
			lastError = time.Now()
		} else {
			c.RefreshLastActive()
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

	mtu            int
	localNet       netip.Prefix
	localAddr      string
	dialer         *corenet.Dialer
	dialerBaseAddr string
	maxQueueSize   int
}

func NewPeerTable(mtu int, device tun.Device, listener net.Listener, localNet netip.Prefix, localAddr string, dialer *corenet.Dialer, dialerBaseAddr string, maxQueueSize int) *PeerTable {
	return &PeerTable{
		isClosed:    false,
		table:       map[string]*PeerConnection{},
		device:      device,
		listener:    listener,
		receiveChan: make(chan *Packet, maxQueueSize),
		pool: sync.Pool{New: func() any {
			return &Packet{Data: make([]byte, mtu+offset), N: 0, Capacity: mtu + offset}
		}},
		mtu:            mtu,
		localNet:       localNet,
		localAddr:      localAddr,
		dialer:         dialer,
		dialerBaseAddr: dialerBaseAddr,
		maxQueueSize:   maxQueueSize,
	}
}

func (t *PeerTable) dialToPeer(s string) (net.Conn, error) {
	conn, err := t.dialer.Dial(path.Join(t.dialerBaseAddr, s))
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := gob.NewEncoder(conn).Encode(PeerHello{FromAddr: t.localAddr, ToAddr: s}); err != nil {
		conn.Close()
		return nil, err
	}
	resp := PeerResponse{}
	if err := gob.NewDecoder(conn).Decode(&resp); err != nil {
		conn.Close()
		return nil, err
	}
	if !resp.Success {
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
			if !t.IsClosed() {
				log.Printf("Tunnel read loop closed: %v, exiting", err)
				t.Close()
			}
			return
		}
		if n == 0 {
			t.pool.Put(packet)
			continue
		}
		packet.N = n + offset
		dst := getDstKeyFromPacket(packet.Data[offset : n+offset])
		dstIP, err := netip.ParseAddr(dst)
		if err != nil {
			t.pool.Put(packet)
			continue
		}
		if t.localNet.Contains(dstIP) {
			t.mu.Lock()
			peerConn, exists := t.table[dst]
			if !exists {
				peerConn = NewConnection(dst, t.dialToPeer, t.receiveChan, &t.pool, t.maxQueueSize)
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
	if !t.IsClosed() {
		log.Printf("Tunnel write loop closed")
		t.Close()
	}
}

func (t *PeerTable) IsClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.isClosed
}

func (t *PeerTable) servePeerIncomingConnnectionLoop() {
	for {
		peerConn, err := t.listener.Accept()
		if err != nil {
			if !t.IsClosed() {
				log.Printf("Tunnel channel closed: %v, exiting", err)
				t.Close()
			}
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
				peerCh = NewConnection(peerHello.FromAddr, t.dialToPeer, t.receiveChan, &t.pool, t.maxQueueSize)
				t.table[peerHello.FromAddr] = peerCh
				go peerCh.ChannelLoop(peerConn)
			} else {
				go peerCh.receiveLoop(peerConn)
			}
		}(peerConn)
	}
}

func (t *PeerTable) backgroundRoutine(done chan struct{}) {
	timer := time.NewTicker(30 * time.Minute)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	defer func() {
		timer.Stop()
		signal.Stop(sigs)
		close(sigs)
	}()

	for {
		select {
		case <-sigs:
			t.Close()
			return
		case <-done:
			return
		case <-timer.C:
			t.mu.Lock()
			if t.isClosed {
				t.mu.Unlock()
				return
			}
			for peer, conn := range t.table {
				if time.Since(conn.LastActive()) > 30*time.Minute {
					conn.Close()
					delete(t.table, peer)
				}
			}
			t.mu.Unlock()
		}
	}
}

func (t *PeerTable) Serve() {
	wg := sync.WaitGroup{}
	wg.Add(3)
	gcDone := make(chan struct{})
	defer close(gcDone)
	go t.backgroundRoutine(gcDone)
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
	log.Printf("Tunnel serve loop closed")
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

func (t *PeerTable) ServeFunc(w http.ResponseWriter, r *http.Request) {
	t.mu.Lock()
	defer t.mu.Unlock()

	keys := make([]string, 0, len(t.table))
	for peerName := range t.table {
		keys = append(keys, peerName)
	}
	sort.Strings(keys)

	fmt.Fprintf(w, "Connection Table %s\n", t.localNet.String())
	for _, peerName := range keys {
		fmt.Fprintf(w, "\nPeer: %s\n", peerName)
		sessionID, err := t.dialer.GetSessionID(path.Join(t.dialerBaseAddr, peerName))
		if err == nil {
			fmt.Fprintf(w, "Session ID: %s\n", sessionID)
		} else {
			fmt.Fprintf(w, "Session lost: %v\n", err)
		}
		fmt.Fprintf(w, "%s\n", t.table[peerName].Status())
	}
}
