/* SPDX-License-Identifier: MIT */

package device

import (
	"sync/atomic"
	"testing"
	"time"
)

type clearCountingEndpoint struct {
	chanEndpoint
	clears *atomic.Int32
}

func (e clearCountingEndpoint) ClearSrc() {
	e.clears.Add(1)
}

func watchClearSrc(peer *Peer) *atomic.Int32 {
	clears := new(atomic.Int32)
	peer.endpoint.Lock()
	peer.endpoint.val = clearCountingEndpoint{chanEndpoint: peer.endpoint.val.(chanEndpoint), clears: clears}
	peer.endpoint.Unlock()
	return clears
}

func stateOf(peer *Peer) handshakeState {
	peer.handshake.mutex.RLock()
	defer peer.handshake.mutex.RUnlock()
	return peer.handshake.state
}

func ageLastInitiation(peer *Peer) {
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now().Add(-2 * RekeyTimeout)
	peer.handshake.mutex.Unlock()
}

// Under steady traffic a new packet, not the retry timer, sends an unanswered
// initiation again: it must clear the endpoint's source as a timer retry does.
func TestResentInitiationClearsSource(t *testing.T) {
	pair := newGiveUpPair(t, true)
	peer := peerOf(t, pair.devA, pair.pkB)
	pkt := buildIPv4Packet(testIPA, testIPB, 8)

	pair.tunA.toDevice <- pkt
	deadline := time.Now().Add(2 * time.Second)
	for stateOf(peer) != handshakeInitiationCreated {
		if time.Now().After(deadline) {
			t.Fatal("no initiation was sent")
		}
		time.Sleep(10 * time.Millisecond)
	}
	clears := watchClearSrc(peer)
	ageLastInitiation(peer)

	pair.tunA.toDevice <- pkt
	deadline = time.Now().Add(2 * time.Second)
	for clears.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the unanswered initiation was sent again without clearing the source")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// An initiation that renews a session whose handshake completed leaves the
// source alone: nothing went unanswered.
func TestRekeyInitiationKeepsSource(t *testing.T) {
	pair := newGiveUpPair(t, false)
	peer := peerOf(t, pair.devA, pair.pkB)
	pkt := buildIPv4Packet(testIPA, testIPB, 8)
	awaitPacket(t, pair.tunB, pkt, func() { pair.tunA.toDevice <- pkt })

	clears := watchClearSrc(peer)
	ageLastInitiation(peer)
	if err := peer.SendHandshakeInitiation(false); err != nil {
		t.Fatal(err)
	}
	if clears.Load() != 0 {
		t.Fatal("renewing a live session cleared the source")
	}
	if stateOf(peer) != handshakeInitiationCreated {
		t.Fatal("no initiation was sent")
	}
}
