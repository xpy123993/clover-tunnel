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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/xpy123993/corenet"
	"golang.zx2c4.com/wireguard/tun"
)

const offset = 4

type PeerHello struct {
	FromAddr string
	ToAddr   string

	Hostname string
}

type PeerResponse struct {
	Success bool
	Reason  string

	Hostname string
}

type Packet struct {
	Data     []byte
	N        int
	Capacity int
}

type PeerConnection struct {
	addr        string
	dialer      func(string) (net.Conn, *PeerResponse, error)
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
	peerHostname           string

	maxQueueSize int
}

func NewConnection(addr string, dialer func(string) (net.Conn, *PeerResponse, error), receiveChan chan *Packet, pool *sync.Pool, maxQueueSize int) *PeerConnection {
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

func (c *PeerConnection) GetHostName() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.peerHostname
}

func (c *PeerConnection) SetHostName(hostname string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.peerHostname = hostname
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
	var resp *PeerResponse
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
				conn, resp, err = c.dialer(c.addr)
				if err == nil {
					go c.receiveLoop(conn)
					c.SetHostName(resp.Hostname)
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

type stringTable struct {
	mu    sync.RWMutex
	table map[string]string
}

func newStringTable() *stringTable {
	return &stringTable{table: make(map[string]string)}
}

func (t *stringTable) Lookup(key string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.table[key]
}

func (t *stringTable) Update(key, val string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.table[key] = val
}

func (t *stringTable) Erase(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.table, key)
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
	hostname       string
	dnsSuffix      string
	dnsTable       *stringTable
}

func NewPeerTable(mtu int, device tun.Device,
	listener net.Listener, localNet netip.Prefix, localAddr string,
	dialer *corenet.Dialer, dialerBaseAddr string,
	maxQueueSize int, hostname string, dnsSuffix string) *PeerTable {
	table := &PeerTable{
		isClosed:    false,
		table:       map[string]*PeerConnection{},
		dnsSuffix:   dnsSuffix,
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
		hostname:       hostname,
		dnsTable:       newStringTable(),
	}
	return table
}

func (t *PeerTable) dialToPeer(s string) (net.Conn, *PeerResponse, error) {
	conn, err := t.dialer.Dial(path.Join(t.dialerBaseAddr, s))
	if err != nil {
		return nil, nil, err
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := gob.NewEncoder(conn).Encode(PeerHello{FromAddr: t.localAddr, ToAddr: s, Hostname: t.hostname}); err != nil {
		conn.Close()
		return nil, nil, err
	}
	resp := PeerResponse{}
	if err := gob.NewDecoder(conn).Decode(&resp); err != nil {
		conn.Close()
		return nil, nil, err
	}
	if !resp.Success {
		conn.Close()
		return nil, nil, fmt.Errorf("app error: %s", resp.Reason)
	}
	conn.SetDeadline(time.Time{})
	t.dnsTable.Update(resp.Hostname, s)
	return conn, &resp, nil
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

func (t *PeerTable) LookupDNS(hostname string) string {
	fullSuffix := "." + t.dnsSuffix + "."
	if !strings.HasSuffix(hostname, fullSuffix) {
		return ""
	}
	return t.dnsTable.Lookup(strings.TrimSuffix(hostname, fullSuffix))
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
			if err := gob.NewEncoder(peerConn).Encode(PeerResponse{Success: true, Hostname: t.hostname}); err != nil {
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
			peerCh.SetHostName(peerHello.Hostname)
			t.dnsTable.Update(peerHello.Hostname, peerHello.FromAddr)
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
					t.dnsTable.Erase(conn.addr)
					conn.Close()
					delete(t.table, peer)
				} else {
					t.dnsTable.Update(conn.peerHostname, conn.addr)
				}
			}
			t.mu.Unlock()
		}
	}
}

func (t *PeerTable) SetupDNSServer() *dns.Server {
	server := &dns.Server{Addr: t.localAddr + ":53", Net: "udp"}
	server.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		msg := dns.Msg{}
		msg.SetReply(r)
		switch r.Question[0].Qtype {
		case dns.TypeA:
			msg.Authoritative = true
			domain := msg.Question[0].Name
			address := t.LookupDNS(r.Question[0].Name)
			if len(address) > 0 {
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP(address),
				})
			}
		}
		w.WriteMsg(&msg)
	})
	return server
}

func (t *PeerTable) Serve() {
	gcDone := make(chan struct{})
	defer close(gcDone)
	go t.backgroundRoutine(gcDone)

	tunnelWait := sync.WaitGroup{}
	tunnelWait.Add(3)
	go func() {
		t.servePeerIncomingConnnectionLoop()
		tunnelWait.Done()
	}()
	go func() {
		t.serveReadDeviceLoop()
		tunnelWait.Done()
	}()
	go func() {
		t.serveWriteDeviceLoop()
		tunnelWait.Done()
	}()
	dnsWait := make(chan struct{})
	dnsQuit := make(chan struct{})
	var dnsServer *dns.Server
	go func() {
		defer close(dnsWait)
		startTime := time.Now()
		var err error
		for time.Since(startTime) < 2*time.Minute {
			dnsServer = t.SetupDNSServer()
			err = dnsServer.ListenAndServe()
			if err != nil {
				select {
				case <-time.After(3 * time.Second):
				case <-dnsQuit:
					return
				}
			} else {
				break
			}
		}
		if err != nil {
			log.Printf("DNS server cannot set up: %v", err)
		}
	}()
	tunnelWait.Wait()
	close(dnsQuit)
	dnsServer.Shutdown()
	<-dnsWait
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
	t.dialer.Close()
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
		peerConn := t.table[peerName]
		fmt.Fprintf(w, "\nPeer: %s\nHostname: %s\n", peerName, fmt.Sprintf("%s.%s", peerConn.GetHostName(), t.dnsSuffix))
		sessionID, err := t.dialer.GetSessionID(path.Join(t.dialerBaseAddr, peerName))
		if err == nil {
			fmt.Fprintf(w, "Session ID: %s\n", sessionID)
		} else {
			fmt.Fprintf(w, "Session lost: %v\n", err)
		}
		fmt.Fprintf(w, "%s\n", peerConn.Status())
	}
}
