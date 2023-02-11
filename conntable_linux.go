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
	cmd.Stdout = os.Stdout
	return cmd.Run()
}

func PostTunnelSetup(localNet *netip.Prefix, devName string) error {
	if err := redirectPipeExecute("ip", "link", "set", "dev", devName, "up"); err != nil {
		log.Printf("Configure tunnel failed: cannot enable TUN device.")
	}
	if err := redirectPipeExecute("ip", "addr", "add", localNet.String(), "dev", devName); err != nil {
		log.Printf("Configure tunnel failed: cannot configure IP address")
	}
	return nil
}

func PostTunnelCleanup(devName string) {
	redirectPipeExecute("ip", "link", "delete", "dev", devName)
	redirectPipeExecute("ip", "tuntap", "del", "mode", "tun", devName)
}
