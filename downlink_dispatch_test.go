package main

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// nopConn — минимальный net.Conn: воркеру нужен только Write.
type nopConn struct{ net.Conn }

func (nopConn) Write(b []byte) (int, error) { return len(b), nil }

// Страж гонки «send on closed channel». Раньше downlinkLoop брал воркера
// (pickDownlinkConn отпускал r.mu) и только потом слал ему в sendCh, а
// unregister в этом окне успевал снять воркера и закрыть канал — отправка
// в закрытый канал роняла паникой ВЕСЬ сервер. Тест гоняет регистрацию,
// снятие и раздачу пакетов параллельно: до фикса падает, после — зелёный,
// в том числе под -race.
func TestDispatchDownlinkVsUnregisterChurn(t *testing.T) {
	r := &rawRouter{sessions: make(map[string]*rawClientSessions)}
	const ip = "10.10.0.2"

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Раздача пакетов — как downlinkLoop.
	pkt := make([]byte, 300)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				r.dispatchDownlink(ip, pkt)
			}
		}()
	}

	// Churn воркеров: relay на мобильных клиентах переподключаются постоянно.
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; ; j++ {
				select {
				case <-stop:
					return
				default:
				}
				w := r.register(ip, nopConn{}, fmt.Sprintf("dev-%d", n))
				r.unregister(ip, w)
			}
		}(i)
	}

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// Пейсер отключается нулём — на этом держится смысл флагов
// -raw-downlink-rate/-raw-downlink-burst.
func TestNewPacerZeroDisables(t *testing.T) {
	if newPacer(0, 16*1024) != nil {
		t.Fatal("rate=0 должен выключать пейсер")
	}
	if newPacer(247*1024, 0) != nil {
		t.Fatal("burst=0 должен выключать пейсер")
	}
	if newPacer(247*1024, 16*1024) == nil {
		t.Fatal("ненулевые значения должны включать пейсер")
	}
	if err := (*pacer)(nil).await(t.Context(), 1500); err != nil {
		t.Fatalf("await на nil-пейсере: %v", err)
	}
	for _, arch := range []string{"mips", "mipsle"} {
		if got := defaultRawDownlinkRate(arch); got != 247*1024 {
			t.Errorf("%s rate = %d, ожидалось %d", arch, got, 247*1024)
		}
		if got := defaultRawDownlinkBurst(arch); got != 16*1024 {
			t.Errorf("%s burst = %d, ожидалось %d", arch, got, 16*1024)
		}
	}
	for _, arch := range []string{"arm64", "amd64"} {
		if got := defaultRawDownlinkRate(arch); got != 0 {
			t.Errorf("%s rate = %d, ожидалось 0 (без пейсера)", arch, got)
		}
		if got := defaultRawDownlinkBurst(arch); got != 0 {
			t.Errorf("%s burst = %d, ожидалось 0 (без пейсера)", arch, got)
		}
	}
}

// Страж ступеней downlinkChunkSizeFor. Верхняя ступень поднята 64 → 256:
// на стенде KN-1010 (MT7621) чанк 64 размазывал один TCP-поток по реле с
// разным latency → reorder на клиенте → DupACK-шторм и обрыв cwnd. Замер
// (одно железо/канал/время): 10-15 Мбит/с при CPU до 90% → 18.6 Мбит/с при
// CPU 43.2%; бюджет CPU на ДОСТАВЛЕННЫЙ пакет 749 → 242 мкс, то есть до
// правки ~68% работы шифрования уходило в ретрансмиссии.
// Границы проверяются на ТОЧНЫХ значениях: ступень задана строгим ">" сверху
// и нестрогим ">=" на остальных, случайная замена одного на другое ловится.
func TestDownlinkChunkSizeForSteps(t *testing.T) {
	cases := []struct {
		pktSize int
		want    int
	}{
		{1500, 256}, // типичный MTU-пакет downlink
		{1101, 256}, // первое значение верхней ступени
		{1100, 24},  // ещё не верхняя ступень
		{702, 24},
		{701, 24}, // нижняя граница ступени 24
		{700, 8},
		{302, 8},
		{301, 8}, // нижняя граница ступени 8
		{300, 3},
		{102, 3},
		{101, 3}, // нижняя граница ступени 3
		{100, 1},
		{40, 1}, // keepalive-размер
		{1, 1},
		{0, 1},
	}
	for _, c := range cases {
		if got := downlinkChunkSizeFor(c.pktSize); got != c.want {
			t.Errorf("downlinkChunkSizeFor(%d) = %d, ожидалось %d", c.pktSize, got, c.want)
		}
	}
}

// Страж значения потолка воркеров и буфера на клиентский IP (MIPS vs ARM).
func TestRawMaxWorkersPerIPValue(t *testing.T) {
	if got := defaultRawMaxWorkersPerIP("mips"); got != 48 {
		t.Fatalf("mips потолок воркеров = %d, ожидалось 48", got)
	}
	if got := defaultRawMaxWorkersPerIP("mipsle"); got != 48 {
		t.Fatalf("mipsle потолок воркеров = %d, ожидалось 48", got)
	}
	if got := defaultRawMaxWorkersPerIP("arm64"); got != 96 {
		t.Fatalf("arm64 потолок воркеров = %d, ожидалось 96", got)
	}
	if got := defaultDownlinkWorkerBuf("mipsle"); got != 256 {
		t.Fatalf("mipsle downlinkWorkerBuf = %d, ожидалось 256", got)
	}
	if got := defaultDownlinkWorkerBuf("arm64"); got != 1024 {
		t.Fatalf("arm64 downlinkWorkerBuf = %d, ожидалось 1024", got)
	}
	// Потолок обязан лежать ВЫШЕ штатного максимума клиента: клиент кратен 9
	// (9/18/27/36), поэтому 36 — рабочая конфигурация, а не край.
	const clientMaxWorkers = 36
	if rawMaxWorkersPerIP <= clientMaxWorkers {
		t.Fatalf("потолок %d не выше штатного максимума клиента %d", rawMaxWorkersPerIP, clientMaxWorkers)
	}
}

// Страж failover в dispatchDownlink: при переполнении очереди текущего
// воркера в режиме flowHash=false пакет уходит в следующий свободный воркер,
// не теряясь и не возвращая буфер дважды.
func TestDispatchDownlinkFailover(t *testing.T) {
	const ip = "10.10.0.4"
	r := &rawRouter{
		sessions:  make(map[string]*rawClientSessions),
		flowHash:  false,
		chunkSize: 8,
	}
	w0 := &downlinkWorker{sendCh: make(chan []byte, 1), done: make(chan struct{})}
	w1 := &downlinkWorker{sendCh: make(chan []byte, 2), done: make(chan struct{})}
	// Забиваем w0 до отказа, не запуская горутину run().
	w0.sendCh <- getBuf2048()[:64]

	r.sessions[ip] = &rawClientSessions{workers: []*downlinkWorker{w0, w1}}

	pkt := []byte{0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 1, 2, 3, 4, 10, 10, 0, 4}
	if !r.dispatchDownlink(ip, pkt) {
		t.Fatal("dispatchDownlink вернул false при доступном резервном воркере")
	}
	if len(w1.sendCh) != 1 {
		t.Fatalf("w1.sendCh len = %d, ожидался 1 после failover", len(w1.sendCh))
	}
	putBuf2048(<-w0.sendCh)
	putBuf2048(<-w1.sendCh)
}

func TestDispatchDownlinkAdaptiveDwell(t *testing.T) {
	if got := resolveRawChunkSize(0); got != 0 {
		t.Fatalf("resolveRawChunkSize(0) = %d, ожидалось 0 (adaptive)", got)
	}
	if got := resolveRawChunkSize(32); got != 32 {
		t.Fatalf("resolveRawChunkSize(32) = %d, ожидалось 32", got)
	}

	const ip = "10.10.0.5"
	r := &rawRouter{
		sessions:  make(map[string]*rawClientSessions),
		flowHash:  false,
		chunkSize: 0,
	}
	w0 := &downlinkWorker{sendCh: make(chan []byte, 4), done: make(chan struct{})}
	w1 := &downlinkWorker{sendCh: make(chan []byte, 4), done: make(chan struct{})}
	cs := &rawClientSessions{
		workers:      []*downlinkWorker{w0, w1},
		rrIndex:      0,
		rrCount:      1,
		chunkStartTs: time.Now().UnixMilli() - downlinkMaxDwellMS - 5,
	}
	r.sessions[ip] = cs

	pkt := make([]byte, 1200)
	pkt[0] = 0x45
	if !r.dispatchDownlink(ip, pkt) {
		t.Fatal("dispatchDownlink вернул false")
	}
	if len(w1.sendCh) != 1 || len(w0.sendCh) != 0 {
		t.Fatalf("после истечения dwell ожидалась ротация на w1: len(w0)=%d len(w1)=%d", len(w0.sendCh), len(w1.sendCh))
	}
	putBuf2048(<-w1.sendCh)
}

func TestRawAdaptiveChunkSizeForSteps(t *testing.T) {
	cases := []struct {
		pktSize int
		want    int
	}{
		{1500, 16},
		{1101, 16},
		{1100, 12},
		{701, 12},
		{700, 8},
		{301, 8},
		{300, 3},
		{101, 3},
		{100, 1},
	}
	for _, c := range cases {
		if got := rawAdaptiveChunkSizeFor(c.pktSize); got != c.want {
			t.Errorf("rawAdaptiveChunkSizeFor(%d) = %d, ожидалось %d", c.pktSize, got, c.want)
		}
	}
}

// Страж формы отказа: сверх потолка register возвращает nil (вызывающий
// закрывает соединение и логирует), а не паникует, не вытесняет живое реле
// и не роняет пакеты молча. Освободившийся слот снова принимает — потолок
// не залипает после отключения клиента.
func TestRegisterRejectsAboveWorkerCap(t *testing.T) {
	r := &rawRouter{sessions: make(map[string]*rawClientSessions)}
	const ip = "10.10.0.3"

	workers := make([]*downlinkWorker, 0, rawMaxWorkersPerIP)
	defer func() {
		for _, w := range workers {
			r.unregister(ip, w)
		}
	}()

	for i := 0; i < rawMaxWorkersPerIP; i++ {
		w := r.register(ip, nopConn{}, "dev")
		if w == nil {
			t.Fatalf("register #%d отвергнут ниже потолка %d", i+1, rawMaxWorkersPerIP)
		}
		workers = append(workers, w)
	}

	if w := r.register(ip, nopConn{}, "dev"); w != nil {
		r.unregister(ip, w)
		t.Fatalf("register сверх потолка %d вернул воркера, ожидался nil", rawMaxWorkersPerIP)
	}
	r.mu.Lock()
	n := len(r.sessions[ip].workers)
	r.mu.Unlock()
	if n != rawMaxWorkersPerIP {
		t.Fatalf("после отказа зарегистрировано %d воркеров, ожидалось %d", n, rawMaxWorkersPerIP)
	}

	r.unregister(ip, workers[0])
	workers = workers[1:]
	w := r.register(ip, nopConn{}, "dev")
	if w == nil {
		t.Fatal("после освобождения слота register всё ещё отвергает")
	}
	workers = append(workers, w)
}
