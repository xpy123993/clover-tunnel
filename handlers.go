package main

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/xpy123993/corenet"
	"golang.zx2c4.com/wireguard/tun"
)

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
		devName = "yuki0"
	}
	listenAddr := *toAddr
	listenAddr.Path = path.Join(toAddr.Path, fromAddr.Host)

	localAddr, err := netip.ParseAddr(fromAddr.Host)
	localNet := netip.PrefixFrom(localAddr, mask)
	if err != nil {
		log.Fatalf("Invalid TUN bind address: %v", err)
	}
	device, err := tun.CreateTUN(devName, mtu)
	if err != nil {
		log.Fatalf("Failed to create TUN device: %v", err)
	}

	log.Printf("Start forwarding: [%s] %v => %v", devName, netip.PrefixFrom(localAddr, mask).String(), listenAddr.String())

	listener, err := createListener(&listenAddr)
	if err != nil {
		log.Fatal(err)
	}

	clientDialer := corenet.NewDialer(
		[]string{toAddr.String()},
		corenet.WithDialerQuicConfig(&quic.Config{KeepAlivePeriod: 5 * time.Second}),
		corenet.WithDialerKCPConfig(corenet.DefaultKCPConfig()),
		corenet.WithDialerBlockMultiListener(listener),
		corenet.WithDialerRelayTLSConfig(tunnelTLSConfig), corenet.WithDialerDirectAccessCIDRBlockList([]netip.Prefix{
			netip.MustParsePrefix("127.0.0.1/8"),
			localNet,
		}))
	connTable := NewPeerTable(mtu, device, listener, localNet, localAddr.String(), clientDialer, toAddr.Path, 1000)
	if len(*debugAddress) > 0 {
		_, port, err := net.SplitHostPort(*debugAddress)
		if err == nil {
			http.HandleFunc("/yukicat/"+devName, connTable.ServeFunc)
			log.Printf("Tunnel state is exposed to http://127.0.0.1:%s/yukicat/%s", port, devName)
		}
	}

	defer device.Close()
	if err := PostTunnelSetup(&localNet, devName); err != nil {
		log.Printf("Cannot configure interface: %v", err)
	}
	connTable.Serve()
	PostTunnelCleanup(devName)
}
