//go:build windows

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
	if err := redirectPipeExecute("netsh", "interface", "ip", "set", "address", "name="+devName, "source=static", "addr="+localNet.String(), "gateway=none"); err != nil {
		log.Printf("Configure tunnel failed.")
	}
	return nil
}

func PostTunnelCleanup(devName string) {
}
