package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type slicePC struct {
	pkts chan []byte
	done chan struct{}
	once sync.Once
}

func newSlicePC() *slicePC {
	return &slicePC{
		pkts: make(chan []byte, 16),
		done: make(chan struct{}),
	}
}

func (s *slicePC) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case p := <-s.pkts:
		n := copy(b, p)
		return n, &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}, nil
	case <-s.done:
		return 0, nil, errors.New("closed")
	}
}

func (s *slicePC) WriteTo([]byte, net.Addr) (int, error) { return 0, nil }
func (s *slicePC) Close() error                          { s.once.Do(func() { close(s.done) }); return nil }
func (s *slicePC) LocalAddr() net.Addr                   { return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (s *slicePC) SetDeadline(time.Time) error           { return nil }
func (s *slicePC) SetReadDeadline(time.Time) error       { return nil }
func (s *slicePC) SetWriteDeadline(time.Time) error      { return nil }

func makeTestTCPPacket(totalLen int, srcPort byte) []byte {
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	pkt[9] = 6
	copy(pkt[12:16], []byte{10, 67, 0, 2})
	copy(pkt[16:20], []byte{93, 158, 134, 1})
	pkt[20] = 0x10
	pkt[21] = srcPort
	pkt[22] = 0x01
	pkt[23] = 0xbb
	return pkt
}

func TestArchBufferProfiles(t *testing.T) {
	for _, arch := range []string{"mips", "mipsle"} {
		if !isMIPSArch(arch) {
			t.Errorf("%s: ожидалось isMIPSArch=true", arch)
		}
		if got := defaultReturnChBuf(arch); got != 384 {
			t.Errorf("%s: defaultReturnChBuf = %d, ожидалось 384", arch, got)
		}
		if got := defaultWorkerSendBuf(arch); got != 128 {
			t.Errorf("%s: defaultWorkerSendBuf = %d, ожидалось 128", arch, got)
		}
	}
	for _, arch := range []string{"arm64", "amd64"} {
		if isMIPSArch(arch) {
			t.Errorf("%s: ожидалось isMIPSArch=false", arch)
		}
		if got := defaultReturnChBuf(arch); got != 512 {
			t.Errorf("%s: defaultReturnChBuf = %d, ожидалось 512", arch, got)
		}
		if got := defaultWorkerSendBuf(arch); got != 256 {
			t.Errorf("%s: defaultWorkerSendBuf = %d, ожидалось 256", arch, got)
		}
	}
}

func TestDispatcherRoutesSmallPacketsToPrioCh(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	src := newSlicePC()
	d := NewRawTunDispatcher(ctx, src, NewStats(), false, 8)
	defer func() {
		_ = src.Close()
		d.Shutdown()
	}()

	slot := &WorkerSlot{
		ID:     1,
		SendCh: make(chan []byte, 4),
		PrioCh: make(chan []byte, 4),
	}
	d.Register(slot)
	defer d.Unregister(slot)

	small := makeTestTCPPacket(52, 1)
	large := makeTestTCPPacket(512, 2)
	src.pkts <- small
	src.pkts <- large

	select {
	case got := <-slot.PrioCh:
		if len(got) != 52 {
			t.Fatalf("PrioCh получил пакет длиной %d, ожидалось 52", len(got))
		}
		putPktBuf(got)
	case <-time.After(2 * time.Second):
		t.Fatal("маленький пакет не попал в PrioCh")
	}

	select {
	case got := <-slot.SendCh:
		if len(got) != 512 {
			t.Fatalf("SendCh получил пакет длиной %d, ожидалось 512", len(got))
		}
		putPktBuf(got)
	case <-time.After(2 * time.Second):
		t.Fatal("крупный пакет не попал в SendCh")
	}
}

func TestDequeueWorkerPktPrioritizesPrioCh(t *testing.T) {
	slot := &WorkerSlot{
		ID:     1,
		SendCh: make(chan []byte, 2),
		PrioCh: make(chan []byte, 2),
	}
	sendPkt := getPktBuf(500)
	prioPkt := getPktBuf(40)
	slot.SendCh <- sendPkt
	slot.PrioCh <- prioPkt

	pkt, ok := dequeueWorkerPkt(t.Context(), slot)
	if !ok || len(pkt) != 40 {
		t.Fatalf("первым должен извлекаться PrioCh (40), получено ok=%v len=%d", ok, len(pkt))
	}
	putPktBuf(pkt)

	pkt, ok = dequeueWorkerPkt(t.Context(), slot)
	if !ok || len(pkt) != 500 {
		t.Fatalf("вторым должен извлекаться SendCh (500), получено ok=%v len=%d", ok, len(pkt))
	}
	putPktBuf(pkt)
}

func TestDispatcherFlowHashDoesNotBlockWhenWorkerFull(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	src := newSlicePC()
	d := NewRawTunDispatcher(ctx, src, NewStats(), true, 8)
	defer func() {
		_ = src.Close()
		d.Shutdown()
	}()

	// Оба слота забиты — flow-hash не должен подвесить readLoop при поступлении
	// новых пакетов, а обязан неблокирующе сбросить переполнение и оставаться отзывчивым.
	s0 := &WorkerSlot{ID: 1, SendCh: make(chan []byte, 1), PrioCh: make(chan []byte, 1)}
	s1 := &WorkerSlot{ID: 2, SendCh: make(chan []byte, 1), PrioCh: make(chan []byte, 1)}
	s0.SendCh <- getPktBuf(200)
	s1.SendCh <- getPktBuf(200)
	d.Register(s0)
	d.Register(s1)

	for i := 0; i < 4; i++ {
		src.pkts <- makeTestTCPPacket(400, byte(10+i))
	}

	// Проверяем, что readLoop не завис и Shutdown завершился вовремя.
	_ = src.Close()
	done := make(chan struct{})
	go func() {
		d.Shutdown()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("readLoop заблокировался при переполненном SendCh в режиме flowHash=true")
	}
	drainWorkerSlot(s0)
	drainWorkerSlot(s1)
}

func TestAdaptiveChunkSizeSteps(t *testing.T) {
	if got := resolveChunkSize(0); got != 0 {
		t.Fatalf("resolveChunkSize(0) = %d, ожидалось 0 (adaptive)", got)
	}
	if got := resolveChunkSize(16); got != 16 {
		t.Fatalf("resolveChunkSize(16) = %d, ожидалось 16", got)
	}
	cases := []struct {
		pktSize int
		want    int
	}{
		{1500, 64},
		{1101, 64},
		{1100, 24},
		{701, 24},
		{700, 8},
		{301, 8},
		{300, 3},
		{101, 3},
		{100, 1},
	}
	for _, c := range cases {
		if got := chunkSizeFor(c.pktSize); got != c.want {
			t.Errorf("chunkSizeFor(%d) = %d, ожидалось %d", c.pktSize, got, c.want)
		}
	}
}
