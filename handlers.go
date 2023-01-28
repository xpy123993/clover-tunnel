package main

import (
	"context"
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"net"
	_ "net/http/pprof"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/xpy123993/corenet"
	"golang.org/x/net/trace"
	"golang.zx2c4.com/wireguard/tun"
)

const offset = 4

type labelledConn struct {
	net.Conn

	tracker trace.Trace
	label   string
	encoder *gob.Encoder
}

type ConnectionTable struct {
	mu        sync.Mutex
	connTable map[string]*labelledConn

	myAddr string
}

func (t *ConnectionTable) lookupOrCreate(address string, dialer func() (net.Conn, error)) (*labelledConn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if conn, exists := t.connTable[address]; exists && conn != nil {
		return conn, nil
	}
	conn, err := dialer()
	if err != nil {
		return nil, err
	}
	t.connTable[address] = &labelledConn{Conn: conn, label: t.myAddr, tracker: trace.New("tunnel", address), encoder: gob.NewEncoder(conn)}
	t.connTable[address].tracker.LazyPrintf("Registered in the connection table (sender)")
	return t.connTable[address], nil
}

func (t *ConnectionTable) mayUpdateConnection(address string, newConn net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	conn, exists := t.connTable[address]
	if exists && conn != nil {
		return false
	}
	t.connTable[address] = &labelledConn{Conn: newConn, label: address, tracker: trace.New("tunnel", address), encoder: gob.NewEncoder(conn)}
	t.connTable[address].tracker.LazyPrintf("Registered in the connection table (receiver)")
	return true
}

func (t *ConnectionTable) removeConn(address string, oldConn net.Conn, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.connTable[address] == oldConn {
		t.connTable[address].tracker.LazyPrintf("Error: %s", reason)
		t.connTable[address].tracker.SetError()
		t.connTable[address].tracker.Finish()
		delete(t.connTable, address)
	}
}

type PeerHello struct {
	FromAddr string `json:"from-addr"`
	ToAddr   string `json:"to-addr"`
}

type PeerResponse struct {
	Success bool   `json:"success"`
	Reason  string `json:"reason"`
}

type Packet struct {
	Data []byte
}

func serveAsRelayServer(relayURL string) {
	server := corenet.NewRelayServer(corenet.WithRelayServerForceEvictChannelSession(true))
	log.Printf("Server starts serving at %s", relayURL)
	if err := server.ServeURL(relayURL, tunnelTLSConfig); err != nil {
		log.Fatalf("Relay server returns error: %v", err)
	}
}

func serverAsPipe(fromAddr, toAddr *url.URL) {
	listener, err := createListener(fromAddr)
	if err != nil {
		log.Fatalf("Failed to process in address: %s", err.Error())
	}
	dialer, err := createDialer(toAddr)
	if err != nil {
		log.Fatalf("Failed to process out address: %s", err.Error())
	}
	log.Printf("Start forwarding: %v => %v", fromAddr, toAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalf("Failed to accept connection: %v", err)
		}
		go func(inConn net.Conn) {
			defer inConn.Close()
			outConn, err := dialer()
			if err != nil {
				log.Printf("Failed to open out connection: %v", err)
				return
			}
			defer outConn.Close()

			ctx, cancelFn := context.WithCancel(context.Background())
			go func() { io.Copy(inConn, outConn); cancelFn() }()
			go func() { io.Copy(outConn, inConn); cancelFn() }()
			<-ctx.Done()
		}(conn)
	}
}

func serveTUNReceiveLoop(Ifce tun.Device, localNet *netip.Prefix, sendFunc func(string, []byte, int)) error {
	mtu, err := Ifce.MTU()
	if err != nil {
		return fmt.Errorf("cannot determine the MTU of the tun device")
	}
	for {
		buf := make([]byte, mtu+offset)
		n, err := Ifce.Read(buf, offset)
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		dst := getDstKeyFromPacket(buf[offset : n+offset])
		dstIP, err := netip.ParseAddr(dst)
		if err != nil {
			continue
		}
		if localNet.Contains(dstIP) {
			// TODO: should use a channel to buffer here.
			go sendFunc(dst, buf[:n+offset], offset)
		}
	}
}

func serveTUNSendLoop(connTable *ConnectionTable, conn net.Conn, mtu int, device tun.Device) {
	packet := Packet{}
	decoder := gob.NewDecoder(conn)
	for {
		if err := decoder.Decode(&packet); err != nil {
			return
		}
		if _, err := device.Write(packet.Data, offset); err != nil {
			log.Fatal(err)
		}
	}
}

func serverAsTun(fromAddr, toAddr *url.URL) {
	mask := 24
	mtu := 1380
	devName := fromAddr.Query().Get("dev")
	if maskStr := fromAddr.Query().Get("mask"); len(maskStr) > 0 {
		mask64, err := strconv.ParseInt(maskStr, 10, 32)
		if err != nil {
			log.Fatalf("invalid mask value, expect an integer, got %v", maskStr)
		}
		mask = int(mask64)
	}
	if mtuStr := fromAddr.Query().Get("mtu"); len(mtuStr) > 0 {
		mtu64, err := strconv.ParseInt(mtuStr, 10, 32)
		if err != nil {
			log.Fatalf("invalid MTU value, expect an integer, got %v", mtuStr)
		}
		mtu = int(mtu64)
	}
	if len(devName) == 0 {
		devName = "tun0"
	}

	listenAddr := *toAddr
	listenAddr.Path = path.Join(toAddr.Path, fromAddr.Host)

	localAddr, err := netip.ParseAddr(fromAddr.Host)
	if err != nil {
		log.Fatalf("Invalid TUN bind address: %v", err)
	}
	device, err := tun.CreateTUN(devName, mtu)
	if err != nil {
		log.Fatalf("Failed to create TUN device: %v", err)
	}
	localNet := netip.PrefixFrom(localAddr, mask)
	log.Printf("Local IP: %s", localAddr)
	log.Printf("Internal net: %s", netip.PrefixFrom(localAddr, mask).String())
	log.Printf("Listening at %s", listenAddr.String())

	clientDialer := corenet.NewDialer(
		[]string{toAddr.String()},
		corenet.WithDialerQuicConfig(&quic.Config{KeepAlivePeriod: 5 * time.Second}),
		corenet.WithDialerKCPConfig(corenet.DefaultKCPConfig()),
		corenet.WithDialerRelayTLSConfig(tunnelTLSConfig), corenet.WithDialerDirectAccessCIDRBlockList([]netip.Prefix{
			netip.MustParsePrefix("127.0.0.1/8"),
			localNet,
		}))

	connTable := ConnectionTable{
		connTable: make(map[string]*labelledConn),
		myAddr:    localAddr.String(),
	}
	defer device.Close()

	go serveTUNReceiveLoop(device, &localNet, func(s string, b []byte, i int) {
		peerConn, err := connTable.lookupOrCreate(s, func() (net.Conn, error) {
			tracker := trace.New("factory", "New connection")
			defer tracker.Finish()
			tracker.LazyPrintf("Connecting to %s", path.Join(toAddr.Path, s))
			conn, err := clientDialer.Dial(path.Join(toAddr.Path, s))
			if err != nil {
				tracker.LazyPrintf(err.Error())
				tracker.SetError()
				return nil, err
			}
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			if err := gob.NewEncoder(conn).Encode(PeerHello{FromAddr: connTable.myAddr, ToAddr: s}); err != nil {
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
			go serveTUNSendLoop(&connTable, conn, mtu, device)
			conn.SetDeadline(time.Time{})
			return conn, nil
		})
		if err != nil {
			return
		}

		peerConn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := peerConn.encoder.Encode(Packet{Data: b}); err != nil {
			defer peerConn.Close()
			connTable.removeConn(s, peerConn, err.Error())
		}
		peerConn.SetDeadline(time.Time{})
	})

	listener, err := createListener(&listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	for ctx.Err() == nil {
		peerConn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func(peerConn net.Conn) {
			defer peerConn.Close()
			peerHello := PeerHello{}
			if err := gob.NewDecoder(peerConn).Decode(&peerHello); err != nil {
				return
			}
			if peerHello.ToAddr != connTable.myAddr {
				gob.NewEncoder(peerConn).Encode(PeerResponse{Success: false, Reason: fmt.Sprintf("expect local addr: %s, got %s", connTable.myAddr, peerHello.ToAddr)})
				return
			}
			if err := gob.NewEncoder(peerConn).Encode(PeerResponse{Success: true}); err != nil {
				return
			}
			connTable.mayUpdateConnection(peerHello.FromAddr, peerConn)
			serveTUNSendLoop(&connTable, peerConn, mtu, device)
		}(peerConn)
	}
}
