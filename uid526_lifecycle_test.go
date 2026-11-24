package sftp

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type uid526FakeFile struct {
	name   string
	closed atomic.Bool
}

func (f *uid526FakeFile) Stat() (os.FileInfo, error) { return nil, nil }
func (f *uid526FakeFile) ReadAt([]byte, int64) (int, error) {
	return 0, io.EOF
}
func (f *uid526FakeFile) WriteAt(b []byte, _ int64) (int, error) { return len(b), nil }
func (f *uid526FakeFile) Readdir(int) ([]os.FileInfo, error)     { return nil, nil }
func (f *uid526FakeFile) Name() string                           { return f.name }
func (f *uid526FakeFile) Truncate(int64) error                   { return nil }
func (f *uid526FakeFile) Chmod(fs.FileMode) error                { return nil }
func (f *uid526FakeFile) Chown(int, int) error                   { return nil }
func (f *uid526FakeFile) Close() error {
	f.closed.Store(true)
	return nil
}

func uid526Pipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = clientConn.Close()
	})
	return serverConn, clientConn
}

func uid526Wait(t *testing.T, timeout time.Duration, fn func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	require.Fail(t, "timed out waiting for condition", msg)
}

func TestUID526_ConnectionStateIsIndependent(t *testing.T) {
	const count = 200
	servers := make([]*Server, count)
	expected := make([]string, count)

	for i := range count {
		serverConn, _ := uid526Pipe(t)
		username := fmt.Sprintf("user-%03d", i)
		srv, err := NewServer(serverConn, WithUsername(username))
		require.NoError(t, err)
		servers[i] = srv
		expected[i] = username
		t.Cleanup(func() { _ = srv.Close() })
	}

	var wg sync.WaitGroup
	for i, srv := range servers {
		wg.Add(1)
		go func(i int, srv *Server) {
			defer wg.Done()
			for range 50 {
				srv.SetUsername(expected[i])
				state := srv.ConnectionState()
				assert.Equal(t, expected[i], state.Username)
			}
		}(i, srv)
	}
	wg.Wait()

	for i, srv := range servers {
		state := srv.ConnectionState()
		assert.Equal(t, expected[i], state.Username)
		assert.Equal(t, HandshakePending, state.Handshake)
	}
}

func TestUID526_TwoHundredConcurrentHandshakesPreserveIdentity(t *testing.T) {
	const count = 200

	servers := make([]*Server, count)
	clients := make([]*Client, count)
	names := make([]string, count)

	for i := range count {
		serverConn, clientConn := net.Pipe()
		name := fmt.Sprintf("stress-user-%03d", i)
		names[i] = name

		srv, err := NewServer(serverConn, WithAuthenticated(name))
		require.NoError(t, err)
		servers[i] = srv
		go func() { _ = srv.Serve() }()

		client, err := NewClientPipe(clientConn, clientConn)
		require.NoError(t, err)
		clients[i] = client
	}

	for i, srv := range servers {
		state := srv.ConnectionState()
		require.Equal(t, HandshakeCompleted, state.Handshake, "connection %d", i)
		require.True(t, state.Authenticated)
		require.Equal(t, names[i], state.Username)
		require.Equal(t, names[i], srv.Username())
	}

	for i, client := range clients {
		_, err := client.RealPath(".")
		require.NoError(t, err, "client %d", i)
	}

	for _, client := range clients {
		_ = client.Close()
	}
	for _, srv := range servers {
		_ = srv.Close()
	}
}

func TestUID526_HandshakeStateTracksProtocolVersion(t *testing.T) {
	client, server := clientServerPair(t)
	defer client.Close()
	defer server.Close()

	uid526Wait(t, 2*time.Second, func() bool {
		return server.ConnectionState().Handshake == HandshakeCompleted
	}, "handshake did not complete")

	state := server.ConnectionState()
	assert.Equal(t, uint32(3), state.ClientVersion)
	assert.Equal(t, uint32(sftpProtocolVersion), state.NegotiatedVersion)
	assert.Equal(t, HandshakeCompleted, state.Handshake)

	wd, err := client.RealPath(".")
	require.NoError(t, err)
	assert.NotEmpty(t, wd)
}

func TestUID526_ClosedStateIsVisibleAfterHandshake(t *testing.T) {
	serverConn, clientConn := uid526Pipe(t)
	srv, err := NewServer(serverConn)
	require.NoError(t, err)
	go func() { _ = srv.Serve() }()

	client, err := NewClientPipe(clientConn, clientConn)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return srv.HandshakeState() == HandshakeCompleted
	}, 2*time.Second, time.Millisecond)

	require.NoError(t, client.Close())
	require.NoError(t, srv.Close())
	assert.Eventually(t, func() bool {
		return srv.HandshakeState() == HandshakeClosed
	}, 2*time.Second, time.Millisecond)
}

func TestUID526_ManagerProbeSupportsAllocatorOption(t *testing.T) {
	manager, err := NewConnectionManager(WithAllocator(), WithMaxConnections(1))
	require.NoError(t, err)

	serverConn, _ := uid526Pipe(t)
	srv, err := manager.NewServer(serverConn)
	require.NoError(t, err)
	require.NotNil(t, srv.pktMgr.alloc)
	require.NoError(t, srv.Close())
	require.NoError(t, manager.Close())
}

func TestUID526_WaitConcurrentWithNewServer(t *testing.T) {
	manager, err := NewConnectionManager()
	require.NoError(t, err)

	var waiters sync.WaitGroup
	for range 4 {
		waiters.Add(1)
		go func() {
			defer waiters.Done()
			for range 100 {
				manager.Wait()
			}
		}()
	}

	for range 200 {
		conn, _ := uid526Pipe(t)
		srv, err := manager.NewServer(conn)
		require.NoError(t, err)
		require.NoError(t, srv.Close())
	}

	waiters.Wait()
	manager.Wait()
	assert.Equal(t, 0, manager.Active())
}

func TestUID526_AuthenticationFailureClosesAndReleasesResources(t *testing.T) {
	serverConn, peer := uid526Pipe(t)
	srv, err := NewServer(serverConn, WithAllocator())
	require.NoError(t, err)

	fake := &uid526FakeFile{name: "leaking-handle"}
	handle := srv.nextHandle(fake)
	page := srv.pktMgr.alloc.GetPage(1)
	require.Len(t, page, maxMsgLength)
	require.Equal(t, 1, srv.pktMgr.alloc.countUsedPages())

	reason := errors.New("bad credentials")
	returned := srv.RejectAuthentication("mixed-up-user", reason)
	assert.ErrorIs(t, returned, reason)
	assert.False(t, srv.IsAuthenticated())
	assert.Equal(t, "mixed-up-user", srv.Username())

	assert.True(t, fake.closed.Load(), "open file handle was not closed")
	_, ok := srv.getHandle(handle)
	assert.False(t, ok)

	lateFake := &uid526FakeFile{name: "opened-during-shutdown"}
	lateHandle := srv.nextHandle(lateFake)
	assert.NotEmpty(t, lateHandle)
	assert.True(t, lateFake.closed.Load(), "handle registered during shutdown leaked")
	_, ok = srv.getHandle(lateHandle)
	assert.False(t, ok)

	assert.Equal(t, 0, srv.pktMgr.alloc.countUsedPages())
	assert.Equal(t, 0, srv.pktMgr.alloc.countAvailablePages())

	buf := make([]byte, 1)
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = peer.Read(buf)
	assert.Error(t, err, "peer was not notified by connection close")

	// Repeated close must remain safe.
	assert.NoError(t, srv.Close())
}

func TestUID526_SetAuthResultSuccessAndFailure(t *testing.T) {
	serverConn, _ := uid526Pipe(t)
	srv, err := NewServer(serverConn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	require.NoError(t, srv.SetAuthResult("alice", nil))
	assert.True(t, srv.IsAuthenticated())
	assert.Equal(t, "alice", srv.Username())

	serverConn2, peer2 := uid526Pipe(t)
	srv2, err := NewServer(serverConn2)
	require.NoError(t, err)
	authErr := errors.New("denied")
	assert.ErrorIs(t, srv2.SetAuthResult("bob", authErr), authErr)
	assert.False(t, srv2.IsAuthenticated())

	_ = peer2.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = peer2.Read(make([]byte, 1))
	assert.Error(t, err)
}

func TestUID526_AuthenticatorFailureClosesConnection(t *testing.T) {
	serverConn, peer := uid526Pipe(t)
	authErr := errors.New("no such principal")
	srv, err := NewServer(serverConn, WithAuthenticator(AuthenticatorFunc(func(info AuthInfo) error {
		assert.Equal(t, "carol", info.Username)
		return authErr
	})))
	require.NoError(t, err)

	err = srv.Authenticate(AuthInfo{Username: "carol", Credential: "secret"})
	assert.ErrorIs(t, err, authErr)
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = peer.Read(make([]byte, 1))
	assert.Error(t, err)
}

func TestUID526_IdleTimeoutClosesConnection(t *testing.T) {
	serverConn, peer := uid526Pipe(t)
	srv, err := NewServer(serverConn, WithIdleTimeout(40*time.Millisecond))
	require.NoError(t, err)

	served := make(chan error, 1)
	go func() { served <- srv.Serve() }()

	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = peer.Read(make([]byte, 1))
	assert.Error(t, err, "idle close did not notify peer")

	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not exit after idle timeout")
	}

	uid526Wait(t, time.Second, func() bool {
		return srv.ConnectionState().Handshake == HandshakeClosed
	}, "closed state was not recorded")
}

func TestUID526_IdleTimeoutUnblocksStalledWrite(t *testing.T) {
	serverConn, _ := uid526Pipe(t)
	srv, err := NewServer(serverConn, WithIdleTimeout(40*time.Millisecond))
	require.NoError(t, err)

	writeDone := make(chan error, 1)
	go func() {
		writeDone <- srv.serverConn.sendPacket(&sshFxpStatusPacket{
			ID: 1,
			StatusError: StatusError{
				Code: sshFxFailure,
				msg:  "this write is never read by the peer",
			},
		})
	}()

	select {
	case err := <-writeDone:
		assert.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("idle close did not unblock a stalled write")
	}
}

func TestUID526_IdleTimeoutActivityResetsTimer(t *testing.T) {
	rwc := &uid526RWC{}
	closed := make(chan struct{})
	ic := newIdleTimeoutConn(rwc, 90*time.Millisecond, func() { close(closed) })
	ic.start()

	for range 4 {
		time.Sleep(30 * time.Millisecond)
		ic.touch()
		select {
		case <-closed:
			t.Fatal("connection timed out despite activity")
		default:
		}
	}

	time.Sleep(150 * time.Millisecond)
	assert.True(t, rwc.closed.Load(), "idle timer did not eventually close connection")
	_ = ic.Close()
}

type uid526RWC struct {
	closed atomic.Bool
}

func (c *uid526RWC) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *uid526RWC) Write(p []byte) (int, error) { return len(p), nil }
func (c *uid526RWC) Close() error {
	c.closed.Store(true)
	return nil
}

func TestUID526_ConnectionLimiterRejectsImmediately(t *testing.T) {
	limiter, err := NewConnectionLimiter(2)
	require.NoError(t, err)

	var servers []*Server
	for range 2 {
		conn, _ := uid526Pipe(t)
		srv, err := NewServer(conn, WithConnectionLimiter(limiter))
		require.NoError(t, err)
		servers = append(servers, srv)
	}
	assert.Equal(t, 2, limiter.Active())

	rejectedConn, rejectedPeer := uid526Pipe(t)
	_, err = NewServer(rejectedConn, WithConnectionLimiter(limiter))
	assert.ErrorIs(t, err, ErrTooManyConnections)
	assert.Equal(t, 2, limiter.Active())

	_ = rejectedPeer.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = rejectedPeer.Read(make([]byte, 1))
	assert.Error(t, err, "rejected connection was not closed")

	require.NoError(t, servers[0].Close())
	assert.Equal(t, 1, limiter.Active())

	conn, _ := uid526Pipe(t)
	srv, err := NewServer(conn, WithConnectionLimiter(limiter))
	require.NoError(t, err)
	assert.Equal(t, 2, limiter.Active())

	for _, srv := range servers[1:] {
		_ = srv.Close()
	}
	_ = srv.Close()
}

func TestUID526_ConnectionManagerTracksAndReusesSlot(t *testing.T) {
	manager, err := NewConnectionManager(WithMaxConnections(1))
	require.NoError(t, err)

	conn1, _ := uid526Pipe(t)
	srv1, err := manager.NewServer(conn1)
	require.NoError(t, err)
	assert.Equal(t, 1, manager.Active())

	conn2, peer2 := uid526Pipe(t)
	srv2, err := manager.NewServer(conn2)
	assert.Nil(t, srv2)
	assert.ErrorIs(t, err, ErrTooManyConnections)
	assert.Equal(t, 1, manager.Active())

	_ = peer2.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = peer2.Read(make([]byte, 1))
	assert.Error(t, err)

	require.NoError(t, srv1.Close())
	assert.Eventually(t, func() bool { return manager.Active() == 0 }, time.Second, time.Millisecond)

	conn3, _ := uid526Pipe(t)
	srv3, err := manager.NewServer(conn3)
	require.NoError(t, err)
	require.NotNil(t, srv3)
	assert.Equal(t, 1, manager.Active())
	require.NoError(t, manager.Close())
	assert.Eventually(t, func() bool { return manager.Active() == 0 }, time.Second, time.Millisecond)
}

func TestUID526_ConnectionManagerServeOverTCPPreservesExistingConnection(t *testing.T) {
	manager, err := NewConnectionManager(
		WithMaxConnections(1),
		WithIdleTimeout(5*time.Second),
	)
	require.NoError(t, err)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveErr := make(chan error, 1)
	go func() { serveErr <- manager.Serve(listener) }()

	t.Cleanup(func() {
		_ = listener.Close()
		_ = manager.Close()
		select {
		case err := <-serveErr:
			assert.NoError(t, err)
		case <-time.After(2 * time.Second):
		}
	})

	conn1, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	client1, err := NewClientPipe(conn1, conn1)
	require.NoError(t, err)
	defer client1.Close()

	require.Eventually(t, func() bool { return manager.Active() == 1 }, 2*time.Second, time.Millisecond)
	_, err = client1.RealPath(".")
	require.NoError(t, err)

	conn2, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer conn2.Close()
	_ = conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn2.Read(make([]byte, 1))
	require.Error(t, err, "over-limit TCP connection was not closed")

	// The first connection remains usable after the rejected attempt.
	_, err = client1.RealPath(".")
	require.NoError(t, err)

	require.NoError(t, client1.Close())
	require.Eventually(t, func() bool { return manager.Active() == 0 }, 2*time.Second, time.Millisecond)

	conn3, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	require.Eventually(t, func() bool { return manager.Active() == 1 }, 2*time.Second, time.Millisecond)
	client3, err := NewClientPipe(conn3, conn3)
	require.NoError(t, err)
	defer client3.Close()
	_, err = client3.RealPath(".")
	require.NoError(t, err)
}

func TestUID526_NewServerOptionErrorClosesTransport(t *testing.T) {
	serverConn, peer := uid526Pipe(t)
	optionErr := errors.New("bad option")
	_, err := NewServer(serverConn, func(*Server) error { return optionErr })
	assert.ErrorIs(t, err, optionErr)

	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = peer.Read(make([]byte, 1))
	assert.Error(t, err)
}

func TestUID526_ServerOptionsRemainCompatible(t *testing.T) {
	conn, _ := uid526Pipe(t)
	srv, err := NewServer(
		conn,
		WithDebug(io.Discard),
		ReadOnly(),
		WithAllocator(),
		WithServerWorkingDirectory("."),
		WithMaxTxPacket(defaultMaxTxPacket),
		WithMaxConnections(10),
		WithIdleTimeout(time.Minute),
		WithHandshakeTimeout(time.Second),
	)
	require.NoError(t, err)
	assert.Equal(t, 10, srv.maxConnections)
	assert.Equal(t, time.Minute, srv.idleTimeout)
	assert.Equal(t, time.Second, srv.handshakeTimeout)
	require.NoError(t, srv.Close())

	_, err = NewServer(conn, WithMaxTxPacket(1))
	assert.Error(t, err)
}
