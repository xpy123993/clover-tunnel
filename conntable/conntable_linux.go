//go:build linux

package conntable

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
	if err := redirectPipeExecute("ip", "tuntap", "del", "mode", "tun", devName); err == nil {
		log.Printf("Clean up is completed")
	}
}
