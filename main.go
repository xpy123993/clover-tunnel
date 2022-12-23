package main

import (
	"crypto/tls"
	"flag"
	"log"
	"os"
)

var (
	tunnelTLSConfig *tls.Config
)

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
