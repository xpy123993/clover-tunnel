package main

import (
	"net"
)

// getDstKeyFromPacket returns the destination key of the packets
func getDstKeyFromPacket(packet []byte) string {
	switch packet[0] >> 4 {
	case 4:
		return net.IP(packet[16:20]).To4().String()
	case 6:
		return net.IP(packet[24:40]).To16().String()
	default:
		return ""
	}
}
