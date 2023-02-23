package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/xpy123993/corenet"
)

var (
	tunnelTLSConfig     *tls.Config
	debugAddress        = flag.String("debug-address", "", "If not empty, an HTTP server will listen on that address.")
	daemonMode          = flag.Bool("daemon", false, "If true, will retry on failure. Should not use in systemd.")
	daemonRetryInterval = flag.Duration("duration", 3*time.Second, "In daemon mode, specifies the retry interval.")
)

func Serve(FromURLString, ToURLString string) {
	tlsConfig, err := getTLSConfigFromEmbeded()
	if err != nil {
		log.Fatalf("Corrupted: cannot load embedded certificate: %v", err)
	}
	tunnelTLSConfig = tlsConfig

	switch FromURLString {
	case "relay":
		serveAsRelayServer(ToURLString)
		return
	case "ls":
		log.SetFlags(0)
		dialer := corenet.NewDialer([]string{ToURLString}, corenet.WithDialerRelayTLSConfig(tunnelTLSConfig))
		channelInfos, err := dialer.GetChannelInfosFromRelay()
		if err != nil {
			log.Printf("Failed to fetch channel infos: %v", err)
		}
		for _, record := range channelInfos {
			log.Printf("  %s\n", record.Channel)
			for _, addr := range record.Addresses {
				log.Printf("    -> %s\n", addr)
			}
			log.Println()
		}
		log.Printf("%d channel(s) in total\n", len(channelInfos))
		return
	}
	fromURL, err := url.Parse(FromURLString)
	if err != nil {
		log.Fatalf("Invalid from addr: %v", err)
	}
	toURL, err := url.Parse(ToURLString)
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
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if handler, exists := debugHandler[r.URL.Path]; exists {
				handler(w, r)
				return
			}
			if r.URL.Path == "/" {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				fmt.Fprintf(w, "<h1> Available path </h1> \n")
				fmt.Fprint(w, "<div><a href='/debug/corenet'>/debug/corenet</a></div>\n")
				for addr := range debugHandler {
					fmt.Fprintf(w, "<div><a href='%s'>%s</a></div>\n", addr, addr)
				}
			}
		})
		go http.ListenAndServe(*debugAddress, nil)
	}

	Serve(flag.Arg(0), flag.Arg(1))
	for *daemonMode {
		log.Printf("Will retry in %s", *daemonRetryInterval)
		time.Sleep(*daemonRetryInterval)
		Serve(flag.Arg(0), flag.Arg(1))
	}
}
