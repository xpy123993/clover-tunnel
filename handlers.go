package main

import (
	"context"
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/xpy123993/corenet"
	"golang.zx2c4.com/wireguard/tun"
)

const offset = 4

type labelledConn struct {
	net.Conn
	label string
}

type ConnectionTable struct {
	mu        sync.Mutex
	connTable map[string]*labelledConn

	myAddr string
}

func (t *ConnectionTable) lookupOrCreate(address string, dialer func() (net.Conn, error)) (net.Conn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if conn, exists := t.connTable[address]; exists && conn != nil {
		return conn, nil
	}
	conn, err := dialer()
	if err != nil {
		return nil, err
	}
	t.connTable[address] = &labelledConn{Conn: conn, label: t.myAddr}
	return conn, nil
}

func (t *ConnectionTable) mayUpdateConnection(address string, newConn net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	conn, exists := t.connTable[address]
	if exists && conn != nil {
		return false
	}
	t.connTable[address] = &labelledConn{Conn: conn, label: address}
	return true
}

func (t *ConnectionTable) removeConn(address string, oldConn net.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.connTable[address] == oldConn {
		delete(t.connTable, address)
	}
}

type PeerHello struct {
	Address string `json:"address"`
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
		if localNet.Contains(dstIP) || dst == "224.0.0.251" {
			go sendFunc(dst, buf[:n+offset], offset)
		}
	}
}

func serveTUNSendLoop(connTable *ConnectionTable, conn net.Conn, mtu int, device tun.Device, updateAddr bool) {
	defer conn.Close()
	peerHello := PeerHello{}
	if err := gob.NewDecoder(conn).Decode(&peerHello); err != nil {
		return
	}
	buf := make([]byte, mtu+offset)
	for {
		n, err := readBuffer(conn, buf[offset:])
		if err != nil {
			return
		}
		if _, err := device.Write(buf[:n+offset], offset); err != nil {
			log.Fatal(err)
		}
		if updateAddr {
			connTable.mayUpdateConnection(peerHello.Address, conn)
			updateAddr = false
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
		conn, err := connTable.lookupOrCreate(s, func() (net.Conn, error) {
			conn, err := clientDialer.Dial(path.Join(toAddr.Path, s))
			if err != nil {
				return nil, err
			}
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			defer conn.SetDeadline(time.Time{})
			if err := gob.NewEncoder(conn).Encode(PeerHello{Address: localAddr.String()}); err != nil {
				conn.Close()
				return nil, err
			}
			go serveTUNSendLoop(&connTable, conn, mtu, device, false)
			return conn, nil
		})
		if err != nil {
			return
		}

		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := writeBuffer(conn, b, i); err != nil {
			defer conn.Close()
			connTable.removeConn(s, conn)
		}
		conn.SetDeadline(time.Time{})
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
		go serveTUNSendLoop(&connTable, peerConn, mtu, device, true)
	}
}
