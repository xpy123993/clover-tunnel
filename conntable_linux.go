//go:build linux

package main

import (
	"log"
	"net/netip"
	"os"
	"os/exec"
)

func redirectPipeExecute(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func PostTunnelSetup(localNet *netip.Prefix, devName, dnsSuffix string) error {
	if err := redirectPipeExecute("ip", "link", "set", "dev", devName, "up"); err != nil {
		log.Printf("Configure tunnel failed: cannot enable TUN device.")
	}
	if err := redirectPipeExecute("ip", "addr", "add", localNet.String(), "dev", devName); err != nil {
		log.Printf("Configure tunnel failed: cannot configure IP address")
	}
	if err := redirectPipeExecute("resolvectl", "dns", devName, localNet.Addr().String()); err != nil {
		log.Printf("Configure tunnel failed: cannot configure interface DNS")
	}
	if err := redirectPipeExecute("resolvectl", "domain", devName, dnsSuffix); err != nil {
		log.Printf("Configure tunnel failed: cannot configure interface DNS domain")
	}
	return nil
}

func PostTunnelCleanup(devName string, dnsSuffix string) {
	redirectPipeExecute("ip", "link", "delete", "dev", devName)
	redirectPipeExecute("ip", "tuntap", "del", "mode", "tun", devName)
}
