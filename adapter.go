package main

import (
	"crypto/rand"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pion/udp/v2"
	"github.com/pkg/errors"
	"github.com/xpy123993/corenet"
)

func createDialer(dialerURL *url.URL) (func() (net.Conn, error), func() error, error) {
	switch dialerURL.Scheme {
	case "tcp", "udp":
		return func() (net.Conn, error) {
			return net.Dial(dialerURL.Scheme, dialerURL.Host)
		}, nil, nil
	default:
		dialer := corenet.NewDialer([]string{dialerURL.String()}, corenet.WithDialerRelayTLSConfig(tunnelTLSConfig))
		return func() (net.Conn, error) {
			return dialer.Dial(dialerURL.Path)
		}, dialer.Close, nil
	}
}

func createCorenetListener(listenerURL *url.URL) (net.Listener, error) {
	opts := corenet.CreateDefaultFallbackOptions()
	opts.TLSConfig = tunnelTLSConfig
	opts.KCPConfig = corenet.DefaultKCPConfig()
	opts.QuicConfig.KeepAlivePeriod = 5 * time.Second
	adapter, err := corenet.CreateListenerFallbackURLAdapter(listenerURL.String(), listenerURL.Path, opts)
	if err != nil {
		return nil, err
	}
	adapters := []corenet.ListenerAdapter{}
	if port := listenerURL.Query().Get("port"); len(port) > 0 {
		portSplit := strings.SplitN(port, "/", 2)
		if len(portSplit) == 1 {
			portSplit = append(portSplit, "tcp")
		}
		iPort, err := strconv.ParseInt(portSplit[0], 10, 32)
		if err != nil {
			return nil, err
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, errors.Wrap(err, "cannot generate key")
		}

		switch portSplit[1] {
		case "udp":
			localAdapter, err := corenet.CreateListenerUDPPortAdapter(int(iPort))
			if err != nil {
				return nil, err
			}
			adapters = append(adapters, localAdapter)
		case "tcp":
			localAdapter, err := corenet.CreateListenerAESTCPPortAdapter(int(iPort), key)
			if err != nil {
				return nil, err
			}
			adapters = append(adapters, localAdapter)
		case "udp+tcp":
			localAdapter, err := corenet.CreateListenerUDPPortAdapter(int(iPort))
			if err != nil {
				return nil, err
			}
			adapters = append(adapters, localAdapter)
			localAdapter, err = corenet.CreateListenerAESTCPPortAdapter(int(iPort), key)
			if err != nil {
				return nil, err
			}
			adapters = append(adapters, localAdapter)
		}

	}
	adapters = append(adapters, adapter)
	return corenet.NewMultiListener(adapters...), nil
}

func createListener(listenerURL *url.URL) (net.Listener, error) {
	switch listenerURL.Scheme {
	case "tcp":
		return net.Listen("tcp", listenerURL.Host)
	case "udp":
		udpAddr, err := net.ResolveUDPAddr("udp", listenerURL.Host)
		if err != nil {
			return nil, err
		}
		return udp.Listen("udp", udpAddr)
	default:
		return createCorenetListener(listenerURL)
	}
}
