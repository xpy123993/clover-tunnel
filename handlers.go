package main

import (
	"context"
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
			go sendFunc(dst, buf[:n+offset], offset)
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
	peerConns := make(map[string]net.Conn, 0)
	mu := sync.Mutex{}
	defer device.Close()
	go serveTUNReceiveLoop(device, &localNet, func(s string, b []byte, i int) {
		mu.Lock()
		conn, exists := peerConns[s]
		if !exists {
			var err error
			conn, err = clientDialer.Dial(path.Join(toAddr.Path, s))
			if err != nil {
				mu.Unlock()
				return
			}
			peerConns[s] = conn
		}
		mu.Unlock()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := writeBuffer(conn, b, i); err != nil {
			defer conn.Close()
			mu.Lock()
			if peerConns[s] == conn {
				delete(peerConns, s)
			}
			mu.Unlock()
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
		go func(conn net.Conn) {
			defer conn.Close()
			buf := make([]byte, mtu+offset)
			for {
				n, err := readBuffer(conn, buf[offset:])
				if err != nil {
					return
				}
				if _, err := device.Write(buf[:n+offset], offset); err != nil {
					log.Fatal(err)
				}
			}
		}(peerConn)
	}
}
