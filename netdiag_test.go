package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// Тот же вектор, что в go_client/netdiag_test.go.
const (
	diagVectorToken = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	diagVectorKey   = "0f2aecd3cd0a9fca825b30c36f38e91e2e81e5a8e4abafd8e758c76fb351702e"
)

func vectorSecret() []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = byte(i)
	}
	return s
}

func TestDiagKeyVector(t *testing.T) {
	if got := diagTokenFromSecret(vectorSecret()); got != diagVectorToken {
		t.Fatalf("token %s", got)
	}
	key, err := deriveDiagKey(vectorSecret())
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(key); got != diagVectorKey {
		t.Fatalf("key %s", got)
	}
}

func TestLoadOrCreateDiagSecretPersists(t *testing.T) {
	dir := t.TempDir()
	a, err := loadOrCreateDiagSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := loadOrCreateDiagSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(a) != hex.EncodeToString(b) || len(a) != 32 {
		t.Fatal("diag secret must survive restarts")
	}
}

func TestWouldBindDeviceMatchesCanConnectAndBind(t *testing.T) {
	cases := []PasswordEntry{
		{MaxDevices: 1},
		{MaxDevices: 1, DeviceIDs: []string{"a"}},
		{MaxDevices: 2, DeviceIDs: []string{"a"}},
		{MaxDevices: 2, DeviceIDs: []string{"a", "b"}},
		{MaxDevices: 1, DeviceID: "a"},
		{MaxDevices: 2, DeviceID: "a"},
		{MaxDevices: 0, DeviceID: "x"},
	}
	for i, c := range cases {
		for _, dev := range []string{"a", "b", "c"} {
			ro := c
			ro.DeviceIDs = append([]string(nil), c.DeviceIDs...)
			rw := c
			rw.DeviceIDs = append([]string(nil), c.DeviceIDs...)
			if got, want := ro.wouldBindDevice(dev), rw.canConnectAndBind(dev); got != want {
				t.Fatalf("case %d dev %s: wouldBind=%v canConnectAndBind=%v", i, dev, got, want)
			}
			if len(ro.DeviceIDs) != len(c.DeviceIDs) || ro.DeviceID != c.DeviceID {
				t.Fatalf("case %d: wouldBindDevice must not modify the entry", i)
			}
		}
	}
}

// ─── Стенд: настоящий wrapPacketListener ───

type diagTestServer struct {
	addr    *net.UDPAddr
	results chan error
}

func setupDiagServer(t *testing.T) *diagTestServer {
	t.Helper()
	setTestDB(t, "main-pass", map[string]*PasswordEntry{
		"good":    {MaxDevices: 1, DeviceIDs: []string{"dev-1"}},
		"old":     {MaxDevices: 1, ExpiresAt: time.Now().Add(-time.Hour).Unix()},
		"off":     {MaxDevices: 1, IsDeactivated: true},
		"full":    {MaxDevices: 1, DeviceIDs: []string{"someone-else"}},
		"roomy":   {MaxDevices: 3, DeviceIDs: []string{"x"}},
		"expired": {ExpiresAt: 1},
	})
	keys := newWrapKeyStore()
	if err := keys.SetPasswords([]string{"good", "full", "roomy"}); err != nil {
		t.Fatal(err)
	}
	oldDiag := serverDiag
	serverDiag = &diagState{
		ports:     map[string]int{},
		seen:      map[string]time.Time{},
		authFails: map[string]*diagAuthFail{},
		tokens:    diagRateBurst,
	}
	t.Cleanup(func() { serverDiag = oldDiag })
	if err := serverDiag.configure(vectorSecret()); err != nil {
		t.Fatal(err)
	}
	serverDiag.setPort("dtls", "0.0.0.0:56000")
	serverDiag.setPort("raw", "0.0.0.0:56003")

	ln, err := listenWrapped("dtls", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}, keys)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &diagTestServer{addr: ln.Addr().(*net.UDPAddr), results: make(chan error, 64)}
	go func() {
		for {
			pc, _, err := ln.Accept()
			if err != nil {
				return
			}
			go func(pc net.PacketConn) {
				defer pc.Close()
				buf := make([]byte, 1600)
				_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
				_, _, err := pc.ReadFrom(buf)
				s.results <- err
			}(pc)
		}
	}()
	return s
}

func clientProbeOnConn(t *testing.T, c *net.UDPConn, addr *net.UDPAddr, key []byte, req diagRequest) (*diagReply, int) {
	t.Helper()
	body, _ := json.Marshal(req)
	payload := append([]byte(diagRequestMagic), body...)
	cfg, err := NewObfsConfig("audio")
	if err != nil {
		t.Fatal(err)
	}
	st, err := NewObfsState()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := obfsWrapPacket(key, payload, cfg, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.WriteToUDP(wire, addr); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	buf := make([]byte, 2048)
	n, err := c.Read(buf)
	if err != nil {
		return nil, 0
	}
	plain := make([]byte, 2048)
	m, err := obfsUnwrapPacket(key, buf[:n], plain)
	if err != nil {
		t.Fatalf("reply does not decrypt with the probe key: %v", err)
	}
	if !strings.HasPrefix(string(plain[:m]), diagReplyMagic) {
		t.Fatalf("not a diag reply: %q", plain[:m])
	}
	var r diagReply
	if err := json.Unmarshal(plain[len(diagReplyMagic):m], &r); err != nil {
		t.Fatal(err)
	}
	if r.Nonce != req.Nonce {
		t.Fatalf("nonce mismatch")
	}
	return &r, m
}

func clientProbe(t *testing.T, srv *diagTestServer, key []byte, req diagRequest) (*diagReply, int) {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return clientProbeOnConn(t, c, srv.addr, key, req)
}

func nonce(i int) string { return strings.Repeat("0", 30) + hex.EncodeToString([]byte{byte(i)}) }

func TestDiagProbeWithPasswordKey(t *testing.T) {
	srv := setupDiagServer(t)
	key, _ := deriveWrapKey("good")
	r, _ := clientProbe(t, srv, key, diagRequest{Nonce: nonce(1), Time: time.Now().Unix(), Device: "dev-1"})
	if r == nil || r.Status != diagStatusOK || r.Listener != "dtls" || r.Ports["raw"] != 56003 {
		t.Fatalf("reply %+v", r)
	}
	if err := <-srv.results; !errors.Is(err, errDiagnosticProbe) {
		t.Fatalf("connection must end with errDiagnosticProbe, got %v", err)
	}
}

func TestDiagProbeWithServerKey(t *testing.T) {
	srv := setupDiagServer(t)
	dkey, _ := deriveDiagKey(vectorSecret())
	cases := []struct {
		pass, dev, want string
	}{
		{"good", "dev-1", diagStatusOK},
		{"main-pass", "anything", diagStatusUnknown},
		{"typo", "dev-1", diagStatusUnknown},
		{"old", "dev-1", diagStatusExpired},
		{"off", "dev-1", diagStatusDeactivated},
		{"full", "dev-1", diagStatusDeviceLimit},
		{"roomy", "new-device", diagStatusOK},
	}
	for i, c := range cases {
		r, _ := clientProbe(t, srv, dkey, diagRequest{Nonce: nonce(10 + i), Time: time.Now().Unix(), PassID: wrapKeyID(c.pass), Device: c.dev})
		if r == nil || r.Status != c.want {
			t.Fatalf("%s: reply %+v, want %s", c.pass, r, c.want)
		}
	}
	if got := db.Passwords["roomy"].DeviceIDs; len(got) != 1 {
		t.Fatalf("diagnostics must not bind devices, got %v", got)
	}
}

func TestDiagProbeReplySizeAndLimits(t *testing.T) {
	srv := setupDiagServer(t)
	key, _ := deriveWrapKey("good")
	r, m := clientProbe(t, srv, key, diagRequest{Nonce: nonce(30), Time: time.Now().Unix(), ReplySize: 1100})
	if r == nil || m != 1100 {
		t.Fatalf("large reply %d bytes, want 1100", m)
	}
	_, m = clientProbe(t, srv, key, diagRequest{Nonce: nonce(31), Time: time.Now().Unix(), ReplySize: 60000})
	if m != diagMaxReply {
		t.Fatalf("reply must be capped at %d, got %d", diagMaxReply, m)
	}
}

func TestDiagProbeRejectsReplayAndStale(t *testing.T) {
	srv := setupDiagServer(t)
	key, _ := deriveWrapKey("good")
	req := diagRequest{Nonce: nonce(40), Time: time.Now().Unix()}
	if r, _ := clientProbe(t, srv, key, req); r == nil {
		t.Fatal("first probe must be answered")
	}
	if r, _ := clientProbe(t, srv, key, req); r != nil {
		t.Fatal("replayed nonce must be ignored")
	}
	stale := diagRequest{Nonce: nonce(41), Time: time.Now().Add(-time.Hour).Unix()}
	if r, _ := clientProbe(t, srv, key, stale); r != nil {
		t.Fatal("stale probe must be ignored")
	}
}

func TestDiagUnknownKeyStaysSilent(t *testing.T) {
	srv := setupDiagServer(t)
	wrong, _ := deriveWrapKey("not-on-server")
	if r, _ := clientProbe(t, srv, wrong, diagRequest{Nonce: nonce(50), Time: time.Now().Unix()}); r != nil {
		t.Fatal("server must not answer a key it does not know")
	}
}

func TestKeepalivePong(t *testing.T) {
	c1, s1 := net.Pipe()
	defer c1.Close()
	defer s1.Close()
	go func() {
		answerKeepalive(s1, 1)
		_ = s1.Close()
	}()
	_ = c1.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 8)
	if n, err := c1.Read(buf); err == nil {
		t.Fatalf("1-byte keepalive must not produce pong, got n=%d", n)
	}

	c2, s2 := net.Pipe()
	defer c2.Close()
	defer s2.Close()
	go func() {
		answerKeepalive(s2, 32)
	}()
	_ = c2.SetReadDeadline(time.Now().Add(time.Second))
	n, err := c2.Read(buf)
	if err != nil {
		t.Fatalf("read keepalive pong: %v", err)
	}
	if n != 1 || buf[0] != keepaliveByte {
		t.Fatalf("unexpected pong: n=%d data=%v", n, buf[:n])
	}
}

type fakeAddrConn struct {
	net.Conn
	local  net.Addr
	remote net.Addr
}

func (f *fakeAddrConn) LocalAddr() net.Addr  { return f.local }
func (f *fakeAddrConn) RemoteAddr() net.Addr { return f.remote }

func TestConnectionCredentialMatches(t *testing.T) {
	local := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 56000}
	remote := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41234}
	udpConn := &fakeAddrConn{local: local, remote: remote}
	id := wrapConnectionBindingID(local, remote)
	t.Cleanup(func() { wrapCredentialBindings.Delete(id) })

	if connectionCredentialMatches(udpConn, "pass-a") {
		t.Fatal("unbound non-pipe connection must be rejected")
	}
	wrapCredentialBindings.Store(id, "pass:"+wrapKeyID("pass-a"))
	if !connectionCredentialMatches(udpConn, "pass-a") {
		t.Fatal("matching credential must be allowed")
	}
	if connectionCredentialMatches(udpConn, "pass-b") {
		t.Fatal("mismatched credential must be rejected")
	}

	pipeC, pipeS := net.Pipe()
	defer pipeC.Close()
	defer pipeS.Close()
	if !connectionCredentialMatches(pipeS, "pass-a") {
		t.Fatal("net.Pipe without binding must stay compatible for unit tests")
	}
	pipeID := wrapConnectionBindingID(pipeS.LocalAddr(), pipeS.RemoteAddr())
	wrapCredentialBindings.Store(pipeID, "pass:"+wrapKeyID("pass-a"))
	t.Cleanup(func() { wrapCredentialBindings.Delete(pipeID) })
	if connectionCredentialMatches(pipeS, "pass-b") {
		t.Fatal("explicit binding mismatch must be rejected even on pipe")
	}
}

func TestReloadDBDisconnectsRevokedSessions(t *testing.T) {
	setTestDB(t, "adminkey", map[string]*PasswordEntry{
		"keep":    {Label: "keep", DeviceIDs: []string{"dev-keep"}},
		"removed": {Label: "removed", DeviceIDs: []string{"dev-rem"}},
		"deact":   {Label: "deact", DeviceIDs: []string{"dev-deact"}},
		"unbound": {Label: "unbound", MaxDevices: 2, DeviceIDs: []string{"dev-stay", "dev-go"}},
	})
	oldFile := dbFile
	dbFile = filepath.Join(t.TempDir(), "passwords.json")
	t.Cleanup(func() { dbFile = oldFile })
	t.Cleanup(func() { _ = serverWrapKeys.SetPasswords(nil) })

	newDB := &Database{
		Passwords: map[string]*PasswordEntry{
			"keep":    {Label: "keep", DeviceIDs: []string{"dev-keep"}},
			"deact":   {Label: "deact", IsDeactivated: true, DeviceIDs: []string{"dev-deact"}},
			"unbound": {Label: "unbound", MaxDevices: 2, DeviceIDs: []string{"dev-stay"}},
		},
		Devices: map[string]*ClientDevice{},
	}
	data, err := json.Marshal(newDB)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbFile, data, 0600); err != nil {
		t.Fatal(err)
	}

	type trackedPair struct {
		peer  net.Conn
		serv  net.Conn
		unreg func()
	}
	mkPair := func(pass, dev string) trackedPair {
		c, s := net.Pipe()
		unreg := trackCredentialConnection(pass, dev, s)
		return trackedPair{peer: c, serv: s, unreg: unreg}
	}
	pKeep := mkPair("keep", "dev-keep")
	pRemoved := mkPair("removed", "dev-rem")
	pDeact := mkPair("deact", "dev-deact")
	pStay := mkPair("unbound", "dev-stay")
	pGo := mkPair("unbound", "dev-go")
	for _, p := range []trackedPair{pKeep, pRemoved, pDeact, pStay, pGo} {
		defer p.unreg()
		defer p.serv.Close()
		defer p.peer.Close()
	}

	if err := reloadDB(nil); err != nil {
		t.Fatalf("reloadDB: %v", err)
	}

	expectClosed := func(name string, peer net.Conn) {
		t.Helper()
		_ = peer.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		buf := make([]byte, 8)
		if _, err := peer.Read(buf); err == nil {
			t.Fatalf("%s connection was expected to be closed", name)
		}
	}
	expectOpen := func(name string, peer net.Conn) {
		t.Helper()
		_ = peer.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
		buf := make([]byte, 8)
		_, err := peer.Read(buf)
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("%s connection closed unexpectedly: %v", name, err)
		}
	}

	expectClosed("removed", pRemoved.peer)
	expectClosed("deactivated", pDeact.peer)
	expectClosed("unbound-device", pGo.peer)
	expectOpen("kept", pKeep.peer)
	expectOpen("stayed-device", pStay.peer)
}

func TestDiagProbeDirectAndRawSequential(t *testing.T) {
	setTestDB(t, "main-pass", map[string]*PasswordEntry{
		"good": {MaxDevices: 1, DeviceIDs: []string{"dev-1"}},
	})
	keys := newWrapKeyStore()
	if err := keys.SetPasswords([]string{"good"}); err != nil {
		t.Fatal(err)
	}
	oldDiag := serverDiag
	serverDiag = &diagState{
		ports:     map[string]int{},
		seen:      map[string]time.Time{},
		authFails: map[string]*diagAuthFail{},
		tokens:    diagRateBurst,
	}
	t.Cleanup(func() { serverDiag = oldDiag })
	if err := serverDiag.configure(vectorSecret()); err != nil {
		t.Fatal(err)
	}

	ln, err := listenWrapped("raw", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}, keys)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverDiag.setPort("raw", ln.Addr().String())

	var doneMu sync.Mutex
	exited := make(chan struct{}, 8)
	go func() {
		for {
			pc, remoteAddr, err := ln.Accept()
			if err != nil {
				return
			}
			go func(pc net.PacketConn, addr net.Addr) {
				dc := &directConn{pc: pc, addr: addr}
				defer dc.Close()
				handleConnRaw(context.Background(), dc, nil)
				doneMu.Lock()
				exited <- struct{}{}
				doneMu.Unlock()
			}(pc, remoteAddr)
		}
	}()

	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()

	key, _ := deriveWrapKey("good")
	srvAddr := ln.Addr().(*net.UDPAddr)

	r1, _ := clientProbeOnConn(t, sock, srvAddr, key, diagRequest{Nonce: nonce(71), Time: time.Now().Unix(), Device: "dev-1"})
	if r1 == nil || r1.Status != diagStatusOK || r1.Listener != "raw" {
		t.Fatalf("first sequential raw probe failed: %+v", r1)
	}
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("first directConn probe handler did not exit promptly")
	}

	r2, m2 := clientProbeOnConn(t, sock, srvAddr, key, diagRequest{Nonce: nonce(72), Time: time.Now().Unix(), Device: "dev-1", ReplySize: 1100})
	if r2 == nil || m2 != 1100 {
		t.Fatalf("second sequential large raw probe failed: r=%+v len=%d", r2, m2)
	}
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("second directConn probe handler did not exit promptly")
	}
}

type stubWGBind struct {
	conn.Bind
	packets   [][]byte
	endpoints []conn.Endpoint
	sent      []conn.Endpoint
}

func (b *stubWGBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	rf := func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		n := len(b.packets)
		for i := 0; i < n; i++ {
			copy(packets[i], b.packets[i])
			sizes[i] = len(b.packets[i])
			endpoints[i] = b.endpoints[i]
		}
		return n, nil
	}
	return []conn.ReceiveFunc{rf}, 51820, nil
}

func (b *stubWGBind) Send(_ [][]byte, endpoint conn.Endpoint) error {
	b.sent = append(b.sent, endpoint)
	return nil
}

type stubEndpoint struct {
	dst netip.Addr
}

func (e stubEndpoint) ClearSrc()           {}
func (e stubEndpoint) SrcToString() string { return "" }
func (e stubEndpoint) DstToString() string { return e.dst.String() }
func (e stubEndpoint) DstToBytes() []byte  { return e.dst.AsSlice() }
func (e stubEndpoint) DstIP() netip.Addr   { return e.dst }
func (e stubEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

func TestLoopbackOnlyBind(t *testing.T) {
	publicEP := stubEndpoint{dst: netip.MustParseAddr("198.51.100.10")}
	loopEP := stubEndpoint{dst: netip.MustParseAddr("127.0.0.1")}

	inner := &stubWGBind{
		packets:   [][]byte{[]byte("pub"), []byte("loop")},
		endpoints: []conn.Endpoint{publicEP, loopEP},
	}
	bind := &loopbackOnlyBind{Bind: inner}

	if err := bind.Send([][]byte{[]byte("x")}, publicEP); err == nil {
		t.Fatal("non-loopback Send must be rejected")
	}
	if err := bind.Send([][]byte{[]byte("x")}, loopEP); err != nil {
		t.Fatalf("loopback Send failed: %v", err)
	}
	if len(inner.sent) != 1 {
		t.Fatalf("expected 1 forwarded Send, got %d", len(inner.sent))
	}

	receivers, _, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	pkts := [][]byte{make([]byte, 32), make([]byte, 32)}
	sizes := make([]int, 2)
	eps := make([]conn.Endpoint, 2)
	n, err := receivers[0](pkts, sizes, eps)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || string(pkts[0][:sizes[0]]) != "loop" || !eps[0].DstIP().IsLoopback() {
		t.Fatalf("expected only loopback packet, got n=%d pkt=%q ep=%v", n, string(pkts[0][:sizes[0]]), eps[0])
	}
}

func TestUntrackKeepsReplacementConnections(t *testing.T) {
	oldConn, _ := net.Pipe()
	newConn, _ := net.Pipe()
	defer oldConn.Close()
	defer newConn.Close()
	untrackOld := trackCredentialConnection("pw-untrack", "dev", oldConn)
	disconnectCredentialConnections("pw-untrack")
	untrackNew := trackCredentialConnection("pw-untrack", "dev", newConn)
	defer untrackNew()
	untrackOld()
	credentialConnections.Lock()
	_, tracked := credentialConnections.items[wrapKeyID("pw-untrack")][newConn]
	credentialConnections.Unlock()
	if !tracked {
		t.Fatal("untrack of a disconnected connection dropped the replacement")
	}
}
