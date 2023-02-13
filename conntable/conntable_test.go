package conntable_test

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xpy123993/corenet"
	"github.com/xpy123993/yukicat/conntable"
)

func TestNoServeClose(t *testing.T) {
	table := conntable.NewPeerTable(context.Background(), nil, nil, nil, 1, &conntable.LocalPeerInfo{
		LocalNet: netip.Prefix{},
	})
	table.Shutdown()
}

func TestServeFailedDueToReadLoopExited(t *testing.T) {
	testDevice := TestDevice{}

	dummyListener := corenet.NewInMemoryListener()
	defer dummyListener.Close()

	dialer := corenet.NewDialer([]string{})
	defer dialer.Close()

	table := conntable.NewPeerTable(context.Background(), &testDevice, dummyListener, dialer, 1, &conntable.LocalPeerInfo{
		LocalNet: netip.Prefix{},
	})
	defer table.Shutdown()

	table.Start()
	if err := table.WaitForShutdown(); err == nil || !strings.Contains(err.Error(), "while serving device read loop") {
		t.Errorf("expect an error indicating read loop failed, got %v", err)
	}
}

func TestServeFailedDueToListenerLoopExited(t *testing.T) {
	dummyListener := corenet.NewInMemoryListener()

	closer := make(chan struct{})
	testDevice := TestDevice{
		readFn: func(b []byte, i int) (int, error) {
			<-closer
			return len(b) - 4, nil
		},
		close: func() error { close(closer); return nil },
	}

	dialer := corenet.NewDialer([]string{})
	defer dialer.Close()

	table := conntable.NewPeerTable(context.Background(), &testDevice, dummyListener, dialer, 1, &conntable.LocalPeerInfo{
		LocalNet: netip.Prefix{},
	})
	table.Start()
	dummyListener.Close()

	if err := table.WaitForShutdown(); err == nil || !strings.Contains(err.Error(), "while serving incoming connection") {
		t.Errorf("expect an error indicating serving incoming connection failed, got %v", err)
	}
}

func createCorenetListener(t *testing.T) (net.Listener, string) {
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lis.Close() })
	localAddr := fmt.Sprintf("tcp://%s", lis.Addr().String())
	return corenet.NewMultiListener(corenet.WithListener(lis, []string{localAddr})), localAddr
}

func httpResonseContainsString(t *testing.T, table *conntable.PeerTable, keywords []string) {
	recorder := httptest.NewRecorder()
	table.ServeFunc(recorder, nil)

	if recorder.Result().StatusCode != http.StatusOK {
		t.Errorf("expect %s to be OK status", http.StatusText(recorder.Result().StatusCode))
	}
	data, _ := io.ReadAll(recorder.Result().Body)
	failed := false
	for _, keyword := range keywords {
		if !strings.Contains(string(data), keyword) {
			t.Errorf("expect to contain keyword `%s`", keyword)
			failed = true
		}
	}
	if failed {
		t.Errorf("response body: %s", string(data))
	}
}

func TestServeSuccessOnePeerPacket(t *testing.T) {
	peerALis, peerADirectAddr := createCorenetListener(t)
	peerBLis, peerBDirectAddr := createCorenetListener(t)

	dialer := corenet.NewDialer([]string{},
		corenet.WithDialerUpdateChannelAddress(false),
		corenet.WithDialerChannelInitialAddress(map[string][]string{
			"/test/192.168.100.1": {peerADirectAddr},
			"/test/192.168.100.2": {peerBDirectAddr},
		}))

	sigReceivedPacket := make(chan struct{})
	completedPeers := sync.WaitGroup{}

	peerSetup := func(device *TestDevice, listener net.Listener, localInfo *conntable.LocalPeerInfo, postVerifyName, postVerifyAddr string) {
		defer completedPeers.Done()
		peerTable := conntable.NewPeerTable(context.Background(), device, listener, dialer, 100, localInfo)
		peerTable.Start()
		<-sigReceivedPacket

		httpResonseContainsString(t, peerTable, []string{fmt.Sprintf("Hostname: %s", postVerifyName), fmt.Sprintf("Peer: %s", postVerifyAddr)})

		peerTable.Shutdown()
		log.Printf("Peer returned: %v", peerTable.WaitForShutdown())
		if !peerTable.IsClosed() {
			t.Error("expect peer table to be returned as closed state")
		}
	}
	completedPeers.Add(2)
	peerACloser := make(chan struct{})
	go peerSetup(&TestDevice{
		readFn: func(b []byte, i int) (int, error) {
			select {
			case <-time.After(20 * time.Millisecond):
			case <-peerACloser:
				return 0, fmt.Errorf("closed")
			}
			b[i] = 4 << 4
			copy(b[i+16:i+20], net.IP{192, 168, 100, 2})
			copy(b[i+20:], "hello world")
			return 31, nil
		},
		close: func() error { close(peerACloser); return nil },
	}, peerALis, &conntable.LocalPeerInfo{
		MTU:         1500,
		Hostname:    "PeerA",
		LocalNet:    netip.MustParsePrefix("192.168.100.1/24"),
		Domain:      "test",
		ChannelRoot: "/test",
	}, "PeerB.test", "192.168.100.2")
	received := atomic.Bool{}
	received.Store(false)
	peerBCloser := make(chan struct{})

	go peerSetup(&TestDevice{
		readFn: func(b []byte, i int) (int, error) {
			<-peerBCloser
			return 0, fmt.Errorf("closed")
		},
		writeFn: func(b []byte, i int) (int, error) {
			if string(b[i+20:i+20+len("hello world")]) != "hello world" {
				t.Errorf("invalid packet received: expect hello world, got %s", string(b[i+20:]))
			}
			if received.CompareAndSwap(false, true) {
				close(sigReceivedPacket)
			}
			return len(b) - i, nil
		},
		close: func() error { close(peerBCloser); return nil },
	}, peerBLis, &conntable.LocalPeerInfo{
		MTU:         1500,
		Hostname:    "PeerB",
		LocalNet:    netip.MustParsePrefix("192.168.100.2/24"),
		Domain:      "test",
		ChannelRoot: "/test",
	}, "PeerA.test", "192.168.100.1")
	<-sigReceivedPacket
	if !received.Load() {
		t.Errorf("PeerB cannot receive hello world packet")
	}
	completedPeers.Wait()
}

func TestStatusPage200(t *testing.T) {
	peerALis, peerADirectAddr := createCorenetListener(t)
	dialer := corenet.NewDialer([]string{},
		corenet.WithDialerUpdateChannelAddress(false),
		corenet.WithDialerChannelInitialAddress(map[string][]string{
			"/test/192.168.100.1": {peerADirectAddr},
		}))

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	peerSetup := func(device *TestDevice, listener net.Listener, localInfo *conntable.LocalPeerInfo) {
		peerTable := conntable.NewPeerTable(ctx, device, listener, dialer, 100, localInfo)
		peerTable.Start()
		httpResonseContainsString(t, peerTable, []string{"192.168.100.1/24"})
		cancel()
		peerTable.WaitForShutdown()
	}
	peerACloser := make(chan struct{})
	go peerSetup(&TestDevice{
		readFn: func(b []byte, i int) (int, error) {
			<-peerACloser
			return 0, fmt.Errorf("closed")
		},
		close: func() error { close(peerACloser); return nil },
	}, peerALis, &conntable.LocalPeerInfo{
		MTU:         1500,
		Hostname:    "PeerA",
		LocalNet:    netip.MustParsePrefix("192.168.100.1/24"),
		Domain:      "test",
		ChannelRoot: "/test",
	})
	<-ctx.Done()
}
