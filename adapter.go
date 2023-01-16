package main

import (
	"fmt"
	"net"
	"net/url"
	"strconv"

	"git.yuki.nu/corenet"
)

func createDialer(dialerURL *url.URL) (func() (net.Conn, error), error) {
	switch dialerURL.Scheme {
	case "tcp":
		return func() (net.Conn, error) {
			return net.Dial("tcp", dialerURL.Host)
		}, nil
	case "ttf":
		dialer := corenet.NewDialer([]string{dialerURL.String()}, corenet.WithDialerRelayTLSConfig(tunnelTLSConfig))
		return func() (net.Conn, error) {
			return dialer.Dial(dialerURL.Path)
		}, nil
	case "ktf":
		dialer := corenet.NewDialer([]string{dialerURL.String()}, corenet.WithDialerRelayTLSConfig(tunnelTLSConfig))
		return func() (net.Conn, error) {
			return dialer.Dial(dialerURL.Path)
		}, nil
	case "quicf":
		dialer := corenet.NewDialer([]string{dialerURL.String()}, corenet.WithDialerRelayTLSConfig(tunnelTLSConfig))
		return func() (net.Conn, error) {
			return dialer.Dial(dialerURL.Path)
		}, nil
	}
	return nil, fmt.Errorf("URL scheme is not supported")
}

func createCorenetListener(listenerURL *url.URL) (net.Listener, error) {
	opts := corenet.CreateDefaultFallbackOptions()
	opts.TLSConfig = tunnelTLSConfig
	adapter, err := corenet.CreateListenerFallbackURLAdapter(listenerURL.String(), listenerURL.Path, opts)
	if err != nil {
		return nil, err
	}
	adapters := []corenet.ListenerAdapter{}
	if port := listenerURL.Query().Get("port"); len(port) > 0 {
		iPort, err := strconv.ParseInt(port, 10, 32)
		if err != nil {
			return nil, err
		}
		localAdapter, err := corenet.CreateListenerTCPPortAdapter(int(iPort))
		if err != nil {
			return nil, err
		}
		adapters = append(adapters, localAdapter)
	}
	adapters = append(adapters, adapter)
	return corenet.NewMultiListener(adapters...), nil
}

func createListener(listenerURL *url.URL) (net.Listener, error) {
	switch listenerURL.Scheme {
	case "tcp":
		return net.Listen("tcp", listenerURL.Host)
	case "ktf":
		return createCorenetListener(listenerURL)
	case "ttf":
		return createCorenetListener(listenerURL)
	case "quicf":
		return createCorenetListener(listenerURL)
	}
	return nil, fmt.Errorf("URL scheme is not supported")
}
