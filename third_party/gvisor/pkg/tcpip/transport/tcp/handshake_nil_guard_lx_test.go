// lx:begin handshake-nil-guard (sing-box-lx SPECS/TASKS/048)

package tcp

import "testing"

// TestHandleConnectingWithNilHandshake pins the guard in handleConnecting.
//
// listenContext.performHandshake, in its failure branch (accept.go), does:
//
//	ep.mu.Lock()
//	ep.h = nil      // handshake destroyed
//	ep.mu.Unlock()  // mutex released — state is still SynSent/SynRecv
//	ep.Close()      // state only changes here, inside closeLocked
//
// A segment arriving between the Unlock and Close wakes the dispatcher, which
// dispatches to handleConnecting because connecting() is still true. Without
// the guard, ep.h.processSegments() dereferences a nil handshake and panics
// with a nil receiver at connect.go — taking down the entire process.
//
// This test recreates that window exactly: no stubbing, the state passes the
// real connecting() gate and control reaches the dereference on its own.
//
// Without the guard this test panics; with it, the segment is a silent no-op.
func TestHandleConnectingWithNilHandshake(t *testing.T) {
	ep := &Endpoint{}
	ep.state.Store(uint32(StateSynRecv))
	ep.h = nil

	if !ep.EndpointState().connecting() {
		t.Fatalf("precondition failed: state %v is not connecting", ep.EndpointState())
	}

	// What processor.start does for an endpoint with a queued segment.
	handleConnecting(ep)

	// The guard must leave the mutex unlocked for the closing side, which is
	// blocked on LockUser inside ep.Close().
	if !ep.TryLock() {
		t.Fatal("handleConnecting returned holding ep.mu — Close() would deadlock")
	}
	ep.mu.Unlock()
}

// lx:end handshake-nil-guard
