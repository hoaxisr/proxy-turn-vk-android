package main

import (
	"encoding/binary"
	"testing"
)

func replayPkt(ssrc, initTs uint32, c uint64) []byte {
	b := make([]byte, rtpHeaderLenLegacy)
	binary.BigEndian.PutUint32(b[4:8], initTs+uint32(c)*960+uint32(c>>16))
	binary.BigEndian.PutUint32(b[8:12], ssrc)
	return b
}

func TestReplayWindow(t *testing.T) {
	const ssrc, initTs = 7, 0xfffff000 // ts переполняется почти сразу
	var w replayWindow
	start := uint64(65530) // c>>16 меняется внутри теста
	for c := start; c < start+100; c++ {
		if !w.accept(replayPkt(ssrc, initTs, c)) {
			t.Fatalf("fresh %d rejected", c)
		}
	}
	if w.accept(replayPkt(ssrc, initTs, start+50)) {
		t.Fatal("replay accepted")
	}
	if !w.accept(replayPkt(ssrc, initTs, start+200)) || !w.accept(replayPkt(ssrc, initTs, start+150)) {
		t.Fatal("reordered packet inside window rejected")
	}
	if w.accept(replayPkt(ssrc, initTs, start+150)) {
		t.Fatal("reordered replay accepted")
	}
	far := start + 200 + replayWindowPackets
	if !w.accept(replayPkt(ssrc, initTs, far)) {
		t.Fatal("jump rejected")
	}
	if w.accept(replayPkt(ssrc, initTs, start+200)) {
		t.Fatal("packet older than window accepted")
	}
	if !w.accept(replayPkt(ssrc, initTs, far-replayWindowPackets+1)) {
		t.Fatal("oldest packet inside window rejected")
	}
	if !w.accept(replayPkt(ssrc, initTs, far+1_000_000)) || w.accept(replayPkt(ssrc, initTs, far+1_000_000)) {
		t.Fatal("big gap broke the window")
	}
	for c := far + 1_000_001; c < far+1_000_001+3*replayWindowPackets; c++ {
		if !w.accept(replayPkt(ssrc, initTs, c)) {
			t.Fatalf("sequential %d rejected: slot not cleared", c)
		}
	}
	if w.accept(replayPkt(ssrc+1, initTs, far+1_000_001)) {
		t.Fatal("foreign ssrc accepted")
	}
}
