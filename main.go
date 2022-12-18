package main

import (
	"context"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"os"

	"git.yuki.nu/corenet"
)

var (
	tunnelTLSConfig *tls.Config
)

func serveAsRelayServer(relayURL string) {
	server := corenet.NewRelayServer(corenet.WithRelayServerForceEvictChannelSession(true))
	log.Printf("Server starts serving at %s", relayURL)
	if err := server.ServeURL(relayURL, tunnelTLSConfig); err != nil {
		log.Fatalf("Relay server returns error: %v", err)
	}
}

func serveAsTunnel(fromAddr, toAddr string) {
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

func main() {
	flag.Parse()

	tlsConfig, err := getTLSConfigFromEmbeded()
	if err != nil {
		log.Fatalf("Corrupted: cannot load embedded certificate: %v", err)
	}
	tunnelTLSConfig = tlsConfig

	if len(os.Args) != 3 {
		log.Fatalf("Invalid args, usage: clover-tunnel [from addr] [to addr]")
	}

	switch os.Args[1] {
	case "relay":
		serveAsRelayServer(os.Args[2])
		return
	}
	serveAsTunnel(os.Args[1], os.Args[2])
}
