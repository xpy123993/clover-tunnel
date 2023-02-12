package conntable_test

import (
	"fmt"
	"os"

	"golang.zx2c4.com/wireguard/tun"
)

type TestDevice struct {
	readFn  func([]byte, int) (int, error)
	writeFn func([]byte, int) (int, error)
	mtu     func() (int, error)
	close   func() error
}

func (d *TestDevice) File() *os.File { return nil }
func (d *TestDevice) Read(b []byte, o int) (int, error) {
	if d.readFn != nil {
		return d.readFn(b, o)
	}
	return 0, fmt.Errorf("unimplemented")
}
func (d *TestDevice) Write(b []byte, o int) (int, error) {
	if d.writeFn != nil {
		return d.writeFn(b, o)
	}
	return 0, fmt.Errorf("unimplemented")
}
func (d *TestDevice) Flush() error { return nil }
func (d *TestDevice) MTU() (int, error) {
	if d.mtu != nil {
		return d.mtu()
	}
	return 0, fmt.Errorf("unimplemented")
}
func (d *TestDevice) Name() (string, error)  { return "", fmt.Errorf("unimplemented") }
func (d *TestDevice) Events() chan tun.Event { return nil }
func (d *TestDevice) Close() error {
	if d.close != nil {
		return d.close()
	}
	return nil
}
