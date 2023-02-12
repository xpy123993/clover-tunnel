package conntable

import (
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

type LocalPeerInfo struct {
	MTU      int
	Hostname string
	LocalNet *netip.Prefix
	Domain   string

	ChannelRoot string
}

type PeerTable struct {
	mu       sync.Mutex
	isClosed bool
	table    map[string]*PeerConnection

	device      tun.Device
	listener    net.Listener
	receiveChan chan *Packet
	pool        sync.Pool

	dialer       *corenet.Dialer
	maxQueueSize int
	localInfo    *LocalPeerInfo

	dnsTable *stringTable
}

func NewPeerTable(device tun.Device, listener net.Listener, dialer *corenet.Dialer, maxQueueSize int, localInfo *LocalPeerInfo) *PeerTable {
	table := &PeerTable{
		isClosed:    false,
		table:       map[string]*PeerConnection{},
		device:      device,
		listener:    listener,
		receiveChan: make(chan *Packet, maxQueueSize),
		pool: sync.Pool{New: func() any {
			return &Packet{Data: make([]byte, localInfo.MTU+offset), N: 0, Capacity: localInfo.MTU + offset}
		}},
		localInfo:    localInfo,
		dialer:       dialer,
		maxQueueSize: maxQueueSize,
		dnsTable:     newStringTable(),
	}
	return table
}

func (t *PeerTable) dialToPeer(s string) (net.Conn, *PeerResponse, error) {
	conn, err := t.dialer.Dial(path.Join(t.localInfo.ChannelRoot, s))
	if err != nil {
		return nil, nil, err
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := gob.NewEncoder(conn).Encode(PeerHello{FromAddr: t.localInfo.LocalNet.Addr().String(), ToAddr: s, Hostname: t.localInfo.Hostname}); err != nil {
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
		if t.localInfo.LocalNet.Contains(dstIP) {
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
			if peerHello.ToAddr != t.localInfo.LocalNet.Addr().String() {
				gob.NewEncoder(peerConn).Encode(PeerResponse{Success: false, Reason: fmt.Sprintf("expect local addr: %s, got %s", t.localInfo.LocalNet.Addr().String(), peerHello.ToAddr)})
				return
			}
			if err := gob.NewEncoder(peerConn).Encode(PeerResponse{Success: true, Hostname: t.localInfo.Hostname}); err != nil {
				return
			}
			t.dnsTable.Update(peerHello.Hostname, peerHello.FromAddr)

			t.mu.Lock()
			peerCh, exists := t.table[peerHello.FromAddr]
			if !exists {
				peerCh = NewConnection(peerHello.FromAddr, t.dialToPeer, t.receiveChan, &t.pool, t.maxQueueSize)
				t.table[peerHello.FromAddr] = peerCh
				t.mu.Unlock()
				peerCh.ChannelLoop(peerConn)
			} else {
				t.mu.Unlock()
				peerCh.receiveLoop(peerConn)
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
					t.dnsTable.Erase(conn.addr)
					conn.Close()
					delete(t.table, peer)
				}
			}
			t.mu.Unlock()
		}
	}
}

func (t *PeerTable) SetupDNSServer() *dns.Server {
	server := &dns.Server{Addr: t.localInfo.LocalNet.Addr().String() + ":53", Net: "udp"}
	server.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		msg := dns.Msg{}
		msg.SetReply(r)
		switch r.Question[0].Qtype {
		case dns.TypeA:
			msg.Authoritative = true
			domain := msg.Question[0].Name
			fullSuffix := "." + t.localInfo.Domain + "."
			if !strings.HasSuffix(domain, fullSuffix) {
				break
			}
			address := t.dnsTable.Lookup(strings.TrimSuffix(domain, fullSuffix))
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

	fmt.Fprintf(w, "Connection Table %s\n", t.localInfo.LocalNet.String())
	for _, peerName := range keys {
		peerConn := t.table[peerName]
		fmt.Fprintf(w, "\nPeer: %s\nHostname: %s\n", peerName, fmt.Sprintf("%s.%s", t.dnsTable.ReverseLookup(peerName), t.localInfo.Domain))
		sessionID, err := t.dialer.GetSessionID(path.Join(t.localInfo.ChannelRoot, peerName))
		if err == nil {
			fmt.Fprintf(w, "Session ID: %s\n", sessionID)
		} else {
			fmt.Fprintf(w, "Session lost: %v\n", err)
		}
		fmt.Fprintf(w, "%s\n", peerConn.Status())
	}
}
