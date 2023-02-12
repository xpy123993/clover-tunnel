package conntable

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
)

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

type stringTable struct {
	mu           sync.RWMutex
	table        map[string]string
	reverseTable map[string]string
}

func newStringTable() *stringTable {
	return &stringTable{table: make(map[string]string), reverseTable: make(map[string]string)}
}

func (t *stringTable) Lookup(key string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.table[key]
}

func (t *stringTable) ReverseLookup(key string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.reverseTable[key]
}

func (t *stringTable) Update(key, val string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.table[key] = val
	t.reverseTable[val] = key
}

func (t *stringTable) Erase(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if val, exist := t.table[key]; exist && len(val) > 0 {
		delete(t.reverseTable, val)
	}
	delete(t.table, key)
}
