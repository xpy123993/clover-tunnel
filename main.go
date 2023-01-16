package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/url"
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
	fromURL, err := url.Parse(os.Args[1])
	if err != nil {
		log.Fatalf("Invalid from addr: %v", err)
	}
	toURL, err := url.Parse(os.Args[2])
	if err != nil {
		log.Fatalf("Invalid to addr: %v", err)
	}
	if fromURL.Scheme == "tun" {
		serverAsTun(fromURL, toURL)
		return
	}
	serverAsPipe(fromURL, toURL)
}
