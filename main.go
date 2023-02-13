package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"net/url"
	"time"
)

var (
	tunnelTLSConfig     *tls.Config
	debugAddress        = flag.String("debug-address", "", "If not empty, an HTTP server will listen on that address.")
	daemonMode          = flag.Bool("daemon", false, "If true, will retry on failure. Should not use in systemd.")
	daemonRetryInterval = flag.Duration("duration", 3*time.Second, "In daemon mode, specifies the retry interval.")
)

func serve() {
	tlsConfig, err := getTLSConfigFromEmbeded()
	if err != nil {
		log.Fatalf("Corrupted: cannot load embedded certificate: %v", err)
	}
	tunnelTLSConfig = tlsConfig

	args := flag.Args()
	if len(args) != 2 {
		log.Fatalf("Invalid args, usage: yukicat [from addr] [to addr]")
	}

	switch args[0] {
	case "relay":
		serveAsRelayServer(args[1])
		return
	}
	fromURL, err := url.Parse(args[0])
	if err != nil {
		log.Fatalf("Invalid from addr: %v", err)
	}
	toURL, err := url.Parse(args[1])
	if err != nil {
		log.Fatalf("Invalid to addr: %v", err)
	}
	if fromURL.Scheme == "tun" {
		serverAsTun(fromURL, toURL)
		return
	}
	serverAsPipe(fromURL, toURL)
}

func main() {
	flag.Parse()
	if len(*debugAddress) > 0 {
		go http.ListenAndServe(*debugAddress, nil)
	}

	serve()
	for *daemonMode {
		log.Printf("Will retry in %s", *daemonRetryInterval)
		time.Sleep(*daemonRetryInterval)
		serve()
	}
}
