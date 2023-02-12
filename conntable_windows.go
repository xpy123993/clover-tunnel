//go:build windows

package main

import (
	"fmt"
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
	if err := redirectPipeExecute("netsh", "interface", "ip", "set", "address", "name="+devName, "source=static", "addr="+localNet.String(), "gateway=none"); err != nil {
		log.Printf("Configure tunnel failed.")
	}
	if err := redirectPipeExecute("powershell.exe", "-Command", "Add-DnsClientNrptRule", "-Namespace", "."+dnsSuffix, "-NameServers", localNet.Addr().String(), "-Comment", devName); err != nil {
		log.Printf("Configure DNS failed.")
	}
	return nil
}

func PostTunnelCleanup(devName string, dnsSuffix string) {
	redirectPipeExecute("powershell.exe", "-Command", fmt.Sprintf("& { Get-DnsClientNrptRule | where Comment -eq '%s' | foreach { Remove-DnsClientNrptRule -Name $_.Name -Force } }", devName))
}
