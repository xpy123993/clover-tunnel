package conntable

import (
	"context"
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
	"github.com/pkg/errors"
	"github.com/xpy123993/corenet"
	"golang.zx2c4.com/wireguard/tun"
)

const offset = 4

type peerHello struct {
	FromAddr string
	ToAddr   string

	Hostname string
}

type peerResponse struct {
	Success bool
	Reason  string

	Hostname string
}

type packet struct {
	Data     []byte
	N        int
	Capacity int
}

type LocalPeerInfo struct {
	MTU      int
	Hostname string
	LocalNet netip.Prefix
	Domain   string

	ChannelRoot string
}

type PeerTable struct {
	mu       sync.Mutex
	isClosed bool
	table    map[string]*PeerConnection

	device      tun.Device
	listener    net.Listener
	receiveChan chan *packet
	pool        sync.Pool

	dialer       *corenet.Dialer
	maxQueueSize int
	localInfo    *LocalPeerInfo

	dnsTable  *stringTable
	dnsServer *dns.Server

	innerContext       context.Context
	innerContextCancel context.CancelCauseFunc
	inflightRoutines   sync.WaitGroup
}

func NewPeerTable(ctx context.Context, device tun.Device, listener net.Listener, dialer *corenet.Dialer, maxQueueSize int, localInfo *LocalPeerInfo) *PeerTable {
	table := &PeerTable{
		isClosed:    false,
		table:       map[string]*PeerConnection{},
		device:      device,
		listener:    listener,
		receiveChan: make(chan *packet, maxQueueSize),
		pool: sync.Pool{New: func() any {
			return &packet{Data: make([]byte, localInfo.MTU+offset), N: 0, Capacity: localInfo.MTU + offset}
		}},
		localInfo:    localInfo,
		dialer:       dialer,
		maxQueueSize: maxQueueSize,
		dnsTable:     newStringTable(),
	}
	table.innerContext, table.innerContextCancel = context.WithCancelCause(ctx)
	table.dnsServer = table.createDNSServer()
	table.inflightRoutines.Add(1)
	go table.backgroundRoutine()
	return table
}

func (t *PeerTable) dialToPeer(s string) (net.Conn, error) {
	if t.innerContext.Err() != nil {
		return nil, fmt.Errorf("PeerTable is closed")
	}
	conn, err := t.dialer.Dial(path.Join(t.localInfo.ChannelRoot, s))
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := gob.NewEncoder(conn).Encode(peerHello{FromAddr: t.localInfo.LocalNet.Addr().String(), ToAddr: s, Hostname: t.localInfo.Hostname}); err != nil {
		conn.Close()
		return nil, err
	}
	resp := peerResponse{}
	if err := gob.NewDecoder(conn).Decode(&resp); err != nil {
		conn.Close()
		return nil, err
	}
	if !resp.Success {
		conn.Close()
		return nil, fmt.Errorf("app error: %s", resp.Reason)
	}
	conn.SetDeadline(time.Time{})
	t.dnsTable.Update(resp.Hostname, s)
	return conn, nil
}

func (t *PeerTable) serveReadDeviceLoop() {
	for t.innerContext.Err() == nil {
		packet := t.pool.Get().(*packet)
		n, err := t.device.Read(packet.Data, offset)
		if err != nil {
			if t.innerContext.Err() == nil {
				t.closeWithError(errors.Wrap(err, "while serving device read loop"))
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
	for t.innerContext.Err() == nil {
		peerConn, err := t.listener.Accept()
		if err != nil {
			if t.innerContext.Err() == nil {
				t.closeWithError(errors.Wrap(err, "while serving incoming connection loop"))
			}
			return
		}
		go func(peerConn net.Conn) {
			peerHello := peerHello{}
			if err := gob.NewDecoder(peerConn).Decode(&peerHello); err != nil {
				return
			}
			if peerHello.ToAddr != t.localInfo.LocalNet.Addr().String() {
				gob.NewEncoder(peerConn).Encode(peerResponse{Success: false, Reason: fmt.Sprintf("expect local addr: %s, got %s", t.localInfo.LocalNet.Addr().String(), peerHello.ToAddr)})
				return
			}
			if err := gob.NewEncoder(peerConn).Encode(peerResponse{Success: true, Hostname: t.localInfo.Hostname}); err != nil {
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

func (t *PeerTable) cleanupObsoleteConnections() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.isClosed {
		return
	}
	for peer, conn := range t.table {
		if time.Since(conn.LastActive()) > 30*time.Minute {
			t.dnsTable.Erase(conn.addr)
			conn.Close()
			delete(t.table, peer)
		}
	}
}

func (t *PeerTable) backgroundRoutine() {
	timer := time.NewTicker(30 * time.Minute)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	defer func() {
		timer.Stop()
		signal.Stop(sigs)
		close(sigs)
		t.inflightRoutines.Done()
	}()

	t.cleanupObsoleteConnections()
	for {
		select {
		case <-sigs:
			t.closeWithError(fmt.Errorf("received exit signal"))
			return
		case <-t.innerContext.Done():
			return
		case <-timer.C:
			t.cleanupObsoleteConnections()
		}
	}
}

func (t *PeerTable) createDNSServer() *dns.Server {
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

func (t *PeerTable) Start() {
	t.inflightRoutines.Add(3)
	go func() {
		t.servePeerIncomingConnnectionLoop()
		t.inflightRoutines.Done()
	}()
	go func() {
		t.serveReadDeviceLoop()
		t.inflightRoutines.Done()
	}()
	go func() {
		t.serveWriteDeviceLoop()
		t.inflightRoutines.Done()
	}()
	t.inflightRoutines.Add(1)
	go func() {
		defer t.inflightRoutines.Done()
		startTime := time.Now()
		var err error
		for time.Since(startTime) < 2*time.Minute {
			err = t.dnsServer.ListenAndServe()
			if err != nil {
				log.Printf("DNS Server setup failed: %v, will retry in 3 seconds", err)
				select {
				case <-time.After(3 * time.Second):
				case <-t.innerContext.Done():
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
}

func (t *PeerTable) WaitForShutdown() error {
	t.inflightRoutines.Wait()
	return context.Cause(t.innerContext)
}

func (t *PeerTable) Serve() {
	t.Start()
	if err := t.WaitForShutdown(); err != nil {
		log.Printf("Serve returned: %v", err)
	}
}

func (t *PeerTable) closeWithError(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.isClosed {
		return
	}
	t.isClosed = true

	t.innerContextCancel(err)
	for _, val := range t.table {
		val.Close()
	}
	if t.listener != nil {
		t.listener.Close()
	}
	if t.device != nil {
		t.device.Close()
	}
	if t.dialer != nil {
		t.dialer.Close()
	}
	if t.dnsServer != nil {
		t.dnsServer.Shutdown()
	}
	close(t.receiveChan)
}

func (t *PeerTable) Shutdown() {
	t.closeWithError(fmt.Errorf("PeerTable is closed"))
	t.inflightRoutines.Wait()
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
