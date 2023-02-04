package main

import (
	"encoding/binary"
	"fmt"
	"io"
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

func writeBuffer(writer io.Writer, buf []byte, offset int) (int, error) {
	if offset < 2 {
		return 0, fmt.Errorf("offset must be at least 2")
	}
	buflength := uint16(len(buf) - offset)
	binary.BigEndian.PutUint16(buf[offset-2:offset], buflength)
	return writer.Write(buf[offset-2:])
}

func readBuffer(reader io.Reader, buf []byte) (int, error) {
	var buflength uint16
	if err := binary.Read(reader, binary.BigEndian, &buflength); err != nil {
		return 0, err
	}
	if int(buflength) > len(buf) {
		return 0, fmt.Errorf("invalid buffer size received")
	}
	return io.ReadFull(reader, buf[:buflength])
}
