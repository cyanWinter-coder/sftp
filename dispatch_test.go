package sftp

import (
	"bytes"
	"context"
	"encoding"
	"errors"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// bufferedConn is an io.ReadWriteCloser whose writes are handed to a buffer
// goroutine. Unlike net.Pipe, a Write does not block waiting for a concurrent
// Read, so a test can inject unsolicited frames while request goroutines are
// parked waiting for replies.
type bufferedConn struct {
	io.Reader
	io.WriteCloser
}

type scriptedRequest struct {
	typ fxp
	id  uint32
}

// scriptedPipe bundles a client-side connection with an inject channel. Bytes
// sent on inject are written to the client by the server goroutine, which keeps
// the write side single-writer (an io.Pipe rejects concurrent writers) while
// still allowing a test to emit unsolicited or duplicate frames.
type scriptedPipe struct {
	conn   *bufferedConn
	inject chan []byte
}

// scriptedServer wires a *Client to a scripted server over buffered pipes.
// The request reader is decoupled from the user-supplied reply function, so a
// reply that blocks never stops the server from draining further requests and
// never deadlocks client writes. After the SSH_FXP_INIT/VERSION handshake each
// request is handed to reply; returning ok==false stops the server.
func scriptedServer(t *testing.T, reply func(typ fxp, id uint32) (fxp, []byte, bool)) scriptedPipe {
	t.Helper()

	cr, sw := io.Pipe() // client reads what the server writes
	sr, cw := io.Pipe() // server reads what the client writes
	cli := &bufferedConn{Reader: cr, WriteCloser: cw}

	requests := make(chan scriptedRequest, 256)
	inject := make(chan []byte, 16)

	go func() {
		defer close(requests)
		for {
			typ, id, ok := readRequest(sr)
			if !ok {
				return
			}
			if typ == sshFxpInit {
				if err := sendPacket(sw, &sshFxVersionPacket{Version: sftpProtocolVersion}); err != nil {
					return
				}
				continue
			}
			select {
			case requests <- scriptedRequest{typ, id}:
			default:
				return
			}
		}
	}()

	go func() {
		defer sw.Close()
		for {
			select {
			case frame, ok := <-inject:
				if !ok {
					return
				}
				if _, err := sw.Write(frame); err != nil {
					return
				}
			case req, ok := <-requests:
				if !ok {
					return
				}
				rtyp, body, keepGoing := reply(req.typ, req.id)
				if !keepGoing {
					return
				}
				if _, err := sw.Write(frameReply(rtyp, body)); err != nil {
					return
				}
			}
		}
	}()
	return scriptedPipe{conn: cli, inject: inject}
}

// okReply builds an SSH_FXP_STATUS/SSH_FX_OK body carrying the echoed id.
func okReply(id uint32) []byte {
	return statusBody(marshalUint32(nil, id), sshFxOk)
}

// Requirement 3: a reply whose id does not match an outstanding request is a
// duplicate or an out-of-order stray. It must be dropped without touching any
// other request's buffer, and the connection must stay alive.
func TestClientDropsUnknownAndDuplicateReplyIDs(t *testing.T) {
	const limit = 4

	var blocked atomic.Uint32
	block := make(chan struct{})

	pipe := scriptedServer(t, func(typ fxp, id uint32) (fxp, []byte, bool) {
		if typ == sshFxpStat {
			// Only hold the first batch outstanding.
			if blocked.Add(1) <= limit {
				<-block
			}
			return sshFxpStatus, okReply(id), true
		}
		return 0, nil, false
	})
	conn := pipe.conn

	c, err := NewClientPipe(conn, conn, MaxConcurrentRequests(limit))
	require.NoError(t, err)
	defer c.Close()

	// Fill the connection with outstanding requests.
	errs := make(chan error, limit)
	for range uint32(limit) {
		id := c.nextID()
		go func() {
			_, _, e := c.sendPacket(context.Background(), nil, &sshFxpStatPacket{ID: id, Path: "/"})
			errs <- e
		}()
	}

	// Wait until all four are registered, then inject an unsolicited reply
	// carrying an id nobody is waiting for.
	require.Eventually(t, func() bool {
		c.Lock()
		n := len(c.inflight)
		c.Unlock()
		return n == limit
	}, time.Second, time.Millisecond)

	unsolicited := uint32(999999)
	pipe.inject <- frameReply(sshFxpStatus, statusBody(marshalUint32(nil, unsolicited), sshFxOk))

	// Let the legitimate replies flow; none may have been displaced by the
	// unsolicited frame.
	close(block)
	for range limit {
		require.NoError(t, <-errs)
	}

	// Now exercise a genuine duplicate: answer a request, then send the same
	// reply again. The duplicate must be discarded rather than killing the
	// connection.
	dup := c.nextID()
	_, _, err = c.sendPacket(context.Background(), nil, &sshFxpStatPacket{ID: dup, Path: "/"})
	require.NoError(t, err)
	pipe.inject <- frameReply(sshFxpStatus, okReply(dup))

	// Connection is still usable: one more ordinary round trip succeeds.
	again := c.nextID()
	_, _, err = c.sendPacket(context.Background(), nil, &sshFxpStatPacket{ID: again, Path: "/"})
	require.NoError(t, err)
}

// Requirement 5: once the per-connection limit of outstanding requests is
// reached, the next request fails immediately with an explicit error and is
// not registered or sent.
func TestClientMaxConcurrentRequestsRejectsExcess(t *testing.T) {
	const limit = 2

	release := make(chan struct{})
	pipe := scriptedServer(t, func(typ fxp, id uint32) (fxp, []byte, bool) {
		if typ == sshFxpStat {
			<-release // keep every request outstanding until the test releases it
			return sshFxpStatus, okReply(id), true
		}
		return 0, nil, false
	})
	conn := pipe.conn

	c, err := NewClientPipe(conn, conn, MaxConcurrentRequests(limit))
	require.NoError(t, err)
	defer c.Close()

	fill := make(chan error, limit)
	for i := 0; i < limit; i++ {
		id := c.nextID()
		go func() {
			_, _, e := c.sendPacket(context.Background(), nil, &sshFxpStatPacket{ID: id, Path: "/"})
			fill <- e
		}()
	}
	require.Eventually(t, func() bool {
		c.Lock()
		n := len(c.inflight)
		c.Unlock()
		return n == limit
	}, time.Second, time.Millisecond)

	// Saturated: a new request must fail immediately rather than block.
	excess := c.nextID()
	done := make(chan error, 1)
	go func() {
		_, _, e := c.sendPacket(context.Background(), nil, &sshFxpStatPacket{ID: excess, Path: "/"})
		done <- e
	}()
	select {
	case e := <-done:
		require.ErrorIs(t, e, ErrMaxConcurrentRequests)
	case <-time.After(time.Second):
		t.Fatal("request over the concurrency limit blocked instead of failing")
	}

	// Nothing was registered for the rejected request.
	c.Lock()
	_, registered := c.inflight[excess]
	inflightCount := len(c.inflight)
	c.Unlock()
	require.False(t, registered, "rejected request must not be registered in inflight")
	require.Equal(t, limit, inflightCount)

	// After the outstanding requests complete, capacity frees up again.
	close(release)
	for i := 0; i < limit; i++ {
		require.NoError(t, <-fill)
	}
	require.Eventually(t, func() bool {
		c.Lock()
		n := len(c.inflight)
		c.Unlock()
		return n == 0
	}, time.Second, time.Millisecond)

	retry := c.nextID()
	_, _, err = c.sendPacket(context.Background(), nil, &sshFxpStatPacket{ID: retry, Path: "/"})
	require.NoError(t, err)
}

// Requirement 5: MaxConcurrentRequests validates its argument and defaults to
// unlimited (zero), preserving the historical behaviour.
func TestMaxConcurrentRequestsOption(t *testing.T) {
	require.Error(t, MaxConcurrentRequests(-1)(&Client{}))

	var c Client
	require.NoError(t, MaxConcurrentRequests(0)(&c))
	require.Zero(t, c.maxInflight)

	require.NoError(t, MaxConcurrentRequests(7)(&c))
	require.Equal(t, 7, c.maxInflight)

	// The default client has no cap.
	var version bytes.Buffer
	require.NoError(t, sendPacket(&version, &sshFxVersionPacket{Version: sftpProtocolVersion}))
	plain, err := NewClientPipe(bytes.NewReader(version.Bytes()), &sink{})
	require.NoError(t, err)
	defer plain.Close()
	require.Zero(t, plain.clientConn.maxInflight)
}

// Requirement 1 & 2: many concurrent transfers, each carrying payloads larger
// than the single-packet limit, must be split on send and reassembled in order
// with every byte routed back to the request that asked for it.
func TestConcurrentLargePayloadsReassembleInOrder(t *testing.T) {
	// maxPacket 32 bytes forces a 256-byte read to be split into 8 packets.
	const (
		packetSize = 32
		fileSize   = 256
		clients    = 10
	)

	block := make([]byte, packetSize)
	for i := range block {
		block[i] = byte(i * 7)
	}
	want := make([]byte, 0, fileSize)
	for len(want) < fileSize {
		want = append(want, block...)
	}

	var handles atomic.Uint32
	pipe := scriptedServer(t, func(typ fxp, id uint32) (fxp, []byte, bool) {
		switch typ {
		case sshFxpOpen:
			// Distinct handles: a repeated handle would be rejected by the client.
			h := handles.Add(1)
			return sshFxpHandle, marshalString(marshalUint32(nil, id), strconv.Itoa(int(h))), true
		case sshFxpRead:
			body := marshalUint32(nil, id)
			body = marshalUint32(body, packetSize)
			body = append(body, block...)
			return sshFxpData, body, true
		case sshFxpClose:
			return sshFxpStatus, okReply(id), true
		default:
			return 0, nil, false
		}
	})
	conn := pipe.conn

	c, err := NewClientPipe(conn, conn, MaxPacket(packetSize))
	require.NoError(t, err)
	defer c.Close()

	var wg sync.WaitGroup
	errs := make(chan error, clients)
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, ferr := c.Open("/file")
			if ferr != nil {
				errs <- ferr
				return
			}
			defer f.Close()
			buf := make([]byte, fileSize)
			n, rerr := f.ReadAt(buf, 0)
			if rerr != nil {
				errs <- rerr
				return
			}
			if n != fileSize {
				errs <- errors.New("short read")
				return
			}
			if string(buf) != string(want) {
				errs <- errors.New("reassembled payload does not match ordered packets")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		require.NoError(t, e)
	}
}

// failingSender implements packetSender: it accepts failAfter packets and then
// reports a write error for every further send.
type failingSender struct {
	mu        sync.Mutex
	failAfter int
	sent      int
	failed    bool
}

func (f *failingSender) sendPacket(encoding.BinaryMarshaler) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent++
	if f.sent <= f.failAfter {
		return nil
	}
	f.failed = true
	return errors.New("simulated broken connection")
}

// Requirement 4: a failed write on the server connection ends request
// processing and every allocated page is returned rather than leaked.
func TestPacketManagerSendErrorReleasesPagesAndStops(t *testing.T) {
	alloc := newAllocator()
	sender := &failingSender{failAfter: 1}
	mgr := newPktMgr(sender)
	mgr.alloc = alloc
	closed := make(chan struct{}, 1)
	mgr.onSendError = func(error) {
		select {
		case <-closed:
		default:
			close(closed)
		}
	}

	// Register three requests and pre-allocate a page for each, then provide
	// matching responses. The first send succeeds, the second fails.
	const requests = 3
	for i := uint32(1); i <= requests; i++ {
		alloc.GetPage(i)
		mgr.incomingPacket(mgr.newOrderedRequest(&sshFxpStatPacket{ID: i}))
	}
	for i := uint32(1); i <= requests; i++ {
		mgr.readyPacket(mgr.newOrderedResponse(&sshFxpStatusPacket{ID: i}, i))
	}

	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("onSendError was not invoked after a write failure")
	}
	// deadNotify fires once the controller has entered draining mode. Responses
	// may still be buffered ahead of it, so poll until every queued page is
	// back rather than asserting at a single instant.
	select {
	case <-mgr.deadNotify:
	case <-time.After(time.Second):
		t.Fatal("packetManager did not enter draining mode")
	}
	require.Eventually(t, func() bool {
		return alloc.countUsedPages() == 0
	}, time.Second, time.Millisecond, "pages leaked after send failure")
	mgr.close()

	require.Equal(t, requests, alloc.countAvailablePages())
	require.True(t, sender.failed, "expected the sender to report a write failure")
}
