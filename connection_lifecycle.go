package sftp

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Common lifecycle errors. Callers can use errors.Is to detect them even when
// an authentication implementation wraps the underlying reason.
var (
	// ErrTooManyConnections is returned when a shared connection limit is full.
	ErrTooManyConnections = errors.New("sftp: too many connections")

	// ErrAuthenticationFailed is a convenience reason used by
	// RejectAuthentication when no more specific error is supplied.
	ErrAuthenticationFailed = errors.New("sftp: authentication failed")

	// ErrAuthenticatorRequired is returned by Server.Authenticate when no
	// Authenticator was configured.
	ErrAuthenticatorRequired = errors.New("sftp: no authenticator configured")

	// ErrConnectionManagerClosed is returned when a closed manager is used.
	ErrConnectionManagerClosed = errors.New("sftp: connection manager closed")
)

// HandshakeState describes the per-connection SFTP handshake lifecycle.
type HandshakeState uint32

const (
	// HandshakePending means the transport exists but SSH_FXP_INIT has not
	// been processed yet.
	HandshakePending HandshakeState = iota
	// HandshakeInitReceived means SSH_FXP_INIT was received.
	HandshakeInitReceived
	// HandshakeCompleted means SSH_FXP_VERSION was selected.
	HandshakeCompleted
	// HandshakeFailed means the handshake could not be completed.
	HandshakeFailed
	// HandshakeClosed means the connection was closed before or after the
	// handshake completed.
	HandshakeClosed
)

// HandshakeStarted is an alias for HandshakeInitReceived.
const HandshakeStarted = HandshakeInitReceived

// String returns a readable name for the handshake state.
func (s HandshakeState) String() string {
	switch s {
	case HandshakePending:
		return "pending"
	case HandshakeInitReceived:
		return "init-received"
	case HandshakeCompleted:
		return "completed"
	case HandshakeFailed:
		return "failed"
	case HandshakeClosed:
		return "closed"
	default:
		return fmt.Sprintf("unknown(%d)", uint32(s))
	}
}

// ConnectionInfo is an immutable snapshot of a connection's handshake and
// authentication state.
type ConnectionInfo struct {
	ID                  uint64
	Handshake           HandshakeState
	ClientVersion       uint32
	NegotiatedVersion   uint32
	Username            string
	Authenticated       bool
	AuthenticationError error
	RemoteAddr          string
	EstablishedAt       time.Time
	LastActivityAt      time.Time
}

// ConnectionStatus is an alias for ConnectionInfo.
type ConnectionStatus = ConnectionInfo

// HandshakeStatus is an alias for HandshakeState.
type HandshakeStatus = HandshakeState

// Handshake status aliases for callers that prefer the "status" terminology.
const (
	HandshakeStatusPending      = HandshakePending
	HandshakeStatusInitReceived = HandshakeInitReceived
	HandshakeStatusStarted      = HandshakeStarted
	HandshakeStatusCompleted    = HandshakeCompleted
	HandshakeStatusFailed       = HandshakeFailed
	HandshakeStatusClosed       = HandshakeClosed
)

// AuthResult is the recorded authentication outcome for one connection.
type AuthResult struct {
	Username      string
	Authenticated bool
	Err           error
}

// AuthInfo contains the principal supplied to an Authenticator. The
// Credential value is intentionally not retained in ConnectionInfo.
type AuthInfo struct {
	Username   string
	Credential any
	RemoteAddr net.Addr
}

// Authenticator validates connection credentials.
type Authenticator interface {
	Authenticate(AuthInfo) error
}

// AuthenticatorFunc adapts a function to the Authenticator interface.
type AuthenticatorFunc func(AuthInfo) error

// Authenticate calls f.
func (f AuthenticatorFunc) Authenticate(info AuthInfo) error {
	return f(info)
}

// connectionState is owned by exactly one Server/connection. It is never
// shared through a package-level variable or another connection.
type connectionState struct {
	mu sync.RWMutex

	id        uint64
	handshake HandshakeState

	clientVersion     uint32
	negotiatedVersion uint32

	username      string
	authenticated bool
	authErr       error

	remoteAddr string

	establishedAt  time.Time
	lastActivityAt time.Time
}

func newConnectionState() *connectionState {
	now := time.Now()
	return &connectionState{
		handshake:      HandshakePending,
		establishedAt:  now,
		lastActivityAt: now,
	}
}

func (s *connectionState) touch() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.lastActivityAt = time.Now()
	s.mu.Unlock()
}

func (s *connectionState) setRemoteAddr(addr string) {
	s.mu.Lock()
	s.remoteAddr = addr
	s.mu.Unlock()
}

func (s *connectionState) setUsername(username string) {
	s.mu.Lock()
	s.username = username
	s.mu.Unlock()
}

func (s *connectionState) setAuthenticated(username string, authenticated bool, err error) {
	s.mu.Lock()
	if username != "" {
		s.username = username
	}
	s.authenticated = authenticated
	s.authErr = err
	s.lastActivityAt = time.Now()
	s.mu.Unlock()
}

func (s *connectionState) initReceived(clientVersion uint32) {
	s.mu.Lock()
	if s.handshake == HandshakePending {
		s.handshake = HandshakeInitReceived
	}
	s.clientVersion = clientVersion
	s.lastActivityAt = time.Now()
	s.mu.Unlock()
}

func (s *connectionState) handshakeCompleted(version uint32) {
	s.mu.Lock()
	s.handshake = HandshakeCompleted
	if s.negotiatedVersion == 0 {
		s.negotiatedVersion = version
	}
	s.lastActivityAt = time.Now()
	s.mu.Unlock()
}

func (s *connectionState) handshakeFailed() {
	s.mu.Lock()
	if s.handshake != HandshakeCompleted {
		s.handshake = HandshakeFailed
	}
	s.mu.Unlock()
}

func (s *connectionState) closed() {
	s.mu.Lock()
	// Closing is terminal, including after a successful handshake. The
	// negotiated version remains available in the snapshot.
	s.handshake = HandshakeClosed
	s.lastActivityAt = time.Now()
	s.mu.Unlock()
}

func (s *connectionState) snapshot() ConnectionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return ConnectionInfo{
		ID:                  s.id,
		Handshake:           s.handshake,
		ClientVersion:       s.clientVersion,
		NegotiatedVersion:   s.negotiatedVersion,
		Username:            s.username,
		Authenticated:       s.authenticated,
		AuthenticationError: s.authErr,
		RemoteAddr:          s.remoteAddr,
		EstablishedAt:       s.establishedAt,
		LastActivityAt:      s.lastActivityAt,
	}
}

// idleTimeoutConn closes the underlying transport after a period without a
// successful Read or Write. The timer is local to one connection.
type idleTimeoutConn struct {
	rwc io.ReadWriteCloser

	mu         sync.Mutex
	timer      *time.Timer
	timeout    time.Duration
	closed     bool
	onActivity func()
	onTimeout  func()

	closeOnce sync.Once
	closeErr  error
}

func newIdleTimeoutConn(rwc io.ReadWriteCloser, timeout time.Duration, onTimeout func()) *idleTimeoutConn {
	// Do not start the timer here. The caller still needs to publish the
	// wrapper and its callbacks; starting it from the constructor can let the
	// timeout observe a partially initialized Server.
	return &idleTimeoutConn{
		rwc:       rwc,
		timeout:   timeout,
		onTimeout: onTimeout,
	}
}

func (c *idleTimeoutConn) start() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed || c.timeout <= 0 || c.timer != nil {
		return
	}
	c.timer = time.AfterFunc(c.timeout, c.expire)
}

func (c *idleTimeoutConn) expire() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()

	// Close the transport first so a packet write blocked by a weak/dead peer
	// is unblocked before server cleanup tries to make progress.
	_ = c.Close()
	if c.onTimeout != nil {
		c.onTimeout()
	}
}

func (c *idleTimeoutConn) setTimeout(timeout time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}

	c.timeout = timeout
	if timeout <= 0 {
		if c.timer != nil {
			c.timer.Stop()
		}
		return
	}

	if c.timer == nil {
		c.timer = time.AfterFunc(timeout, c.expire)
	} else {
		c.timer.Reset(timeout)
	}
}

func (c *idleTimeoutConn) touch() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}

	if c.timeout > 0 && c.timer != nil {
		c.timer.Reset(c.timeout)
	}
	activity := c.onActivity
	c.mu.Unlock()

	if activity != nil {
		activity()
	}
}

func (c *idleTimeoutConn) Read(p []byte) (int, error) {
	n, err := c.rwc.Read(p)
	c.touch()
	return n, err
}

func (c *idleTimeoutConn) Write(p []byte) (int, error) {
	// A write in progress is activity too. Resetting before the write prevents
	// a slow write from being reaped midway through a packet.
	c.touch()
	n, err := c.rwc.Write(p)
	c.touch()
	return n, err
}

// CloseWrite forwards half-close when the transport supports it. SSH channels
// and TCP connections use this to deliver EOF before the full close.
func (c *idleTimeoutConn) CloseWrite() error {
	if cw, ok := c.rwc.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.New("sftp: transport does not support close-write")
}

func (c *idleTimeoutConn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		if c.timer != nil {
			c.timer.Stop()
		}
		c.mu.Unlock()

		c.closeErr = c.rwc.Close()
	})
	return c.closeErr
}

// ConnectionLimiter is a shared, non-blocking concurrency limit. Acquire fails
// immediately with ErrTooManyConnections instead of queueing new connections.
type ConnectionLimiter struct {
	maxConnections int

	mu     sync.Mutex
	active int
}

// NewConnectionLimiter creates a limiter. A maxConnections value of zero means
// unlimited; negative values are invalid.
func NewConnectionLimiter(maxConnections int) (*ConnectionLimiter, error) {
	if maxConnections < 0 {
		return nil, errors.New("sftp: max connections must be greater than or equal to zero")
	}
	return &ConnectionLimiter{maxConnections: maxConnections}, nil
}

// Acquire reserves one connection slot. The returned function releases it.
func (l *ConnectionLimiter) Acquire() (func(), error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.maxConnections > 0 && l.active >= l.maxConnections {
		return nil, fmt.Errorf("%w: limit %d", ErrTooManyConnections, l.maxConnections)
	}

	l.active++
	var once sync.Once
	return func() {
		once.Do(l.Release)
	}, nil
}

// Release returns one slot.
func (l *ConnectionLimiter) Release() {
	l.mu.Lock()
	if l.active > 0 {
		l.active--
	}
	l.mu.Unlock()
}

// Active returns the number of held slots.
func (l *ConnectionLimiter) Active() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.active
}

// ActiveCount is an alias for Active.
func (l *ConnectionLimiter) ActiveCount() int { return l.Active() }

// Count is an alias for Active.
func (l *ConnectionLimiter) Count() int { return l.Active() }

// MaxConnections returns the configured limit; zero means unlimited.
func (l *ConnectionLimiter) MaxConnections() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.maxConnections
}

// ConnectionManager owns a shared connection limit and tracks live Servers.
// A zero limit means unlimited.
type ConnectionManager struct {
	maxConnections int
	idleTimeout    time.Duration

	serverOptions []ServerOption

	mu      sync.Mutex
	servers map[*Server]struct{}
	closed  bool
	idle    chan struct{}

	closeOnce sync.Once
}

// NewConnectionManager creates a manager. Lifecycle ServerOptions such as
// WithMaxConnections and WithIdleTimeout configure the manager; all other
// supplied ServerOptions become defaults for servers created by the manager.
func NewConnectionManager(options ...ServerOption) (*ConnectionManager, error) {
	settings, err := probeLifecycleOptions(options)
	if err != nil {
		return nil, err
	}

	closedIdle := make(chan struct{})
	close(closedIdle)
	m := &ConnectionManager{
		maxConnections: settings.maxConnections,
		idleTimeout:    settings.idleTimeout,
		serverOptions:  append([]ServerOption(nil), options...),
		servers:        make(map[*Server]struct{}),
		idle:           closedIdle,
	}
	return m, nil
}

// ConnectionPool is alternate terminology for ConnectionManager.
type ConnectionPool = ConnectionManager

// NewConnectionPool is an alias for NewConnectionManager.
func NewConnectionPool(options ...ServerOption) (*ConnectionPool, error) {
	return NewConnectionManager(options...)
}

// NewConnectionManagerWithLimit is a concise constructor for the common case.
// A zero maxConnections or idleTimeout means unlimited/no idle timeout.
func NewConnectionManagerWithLimit(maxConnections int, idleTimeout time.Duration, options ...ServerOption) (*ConnectionManager, error) {
	all := make([]ServerOption, 0, len(options)+2)
	all = append(all, WithMaxConnections(maxConnections), WithIdleTimeout(idleTimeout))
	all = append(all, options...)
	return NewConnectionManager(all...)
}

func probeLifecycleOptions(options []ServerOption) (*Server, error) {
	state := newConnectionState()
	probe := &Server{
		serverConn:      &serverConn{},
		connectionState: state,
		lifecycle:       state,
		pktMgr:          &packetManager{},
	}
	for _, option := range options {
		if err := option(probe); err != nil {
			return nil, err
		}
	}
	return probe, nil
}

// NewServer creates an SFTP Server tracked by the manager. When the limit is
// full it closes rwc and returns ErrTooManyConnections without affecting
// existing servers.
func (m *ConnectionManager) NewServer(rwc io.ReadWriteCloser, options ...ServerOption) (*Server, error) {
	if m == nil {
		return NewServer(rwc, options...)
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		_ = rwc.Close()
		return nil, ErrConnectionManagerClosed
	}
	m.mu.Unlock()

	all := make([]ServerOption, 0, len(m.serverOptions)+len(options)+1)
	all = append(all, m.serverOptions...)
	all = append(all, options...)
	all = append(all, WithConnectionManager(m))

	srv, err := NewServer(rwc, all...)
	if err != nil {
		return nil, err
	}
	return srv, nil
}

// Handle is an alias for NewServer.
func (m *ConnectionManager) Handle(rwc io.ReadWriteCloser, options ...ServerOption) (*Server, error) {
	return m.NewServer(rwc, options...)
}

func (m *ConnectionManager) attach(srv *Server) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrConnectionManagerClosed
	}
	if m.maxConnections > 0 && len(m.servers) >= m.maxConnections {
		return fmt.Errorf("%w: limit %d", ErrTooManyConnections, m.maxConnections)
	}

	if len(m.servers) == 0 {
		m.idle = make(chan struct{})
	}
	m.servers[srv] = struct{}{}
	return nil
}

func (m *ConnectionManager) detach(srv *Server) {
	m.mu.Lock()
	if _, ok := m.servers[srv]; !ok {
		m.mu.Unlock()
		return
	}
	delete(m.servers, srv)
	if len(m.servers) == 0 {
		close(m.idle)
	}
	m.mu.Unlock()
}

// Active returns the number of tracked live servers.
func (m *ConnectionManager) Active() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.servers)
}

// ActiveCount is an alias for Active.
func (m *ConnectionManager) ActiveCount() int { return m.Active() }

// Count is an alias for Active.
func (m *ConnectionManager) Count() int { return m.Active() }

// Len is an alias for Active.
func (m *ConnectionManager) Len() int { return m.Active() }

// Wait blocks until every attached server has detached. It is safe to call
// concurrently with NewServer; a connection that attaches after Wait observes
// an already-closed idle generation belongs to the next Wait generation.
func (m *ConnectionManager) Wait() {
	m.mu.Lock()
	idle := m.idle
	m.mu.Unlock()
	<-idle
}

// Close closes the manager and every currently tracked server. New servers
// are rejected afterwards.
func (m *ConnectionManager) Close() error {
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		servers := make([]*Server, 0, len(m.servers))
		for srv := range m.servers {
			servers = append(servers, srv)
		}
		m.mu.Unlock()

		for _, srv := range servers {
			_ = srv.Close()
		}
		m.Wait()
	})
	return nil
}

// Serve accepts network connections and serves one independent SFTP Server
// per connection. Rejected connections are closed immediately and do not
// stop the accept loop.
func (m *ConnectionManager) Serve(listener net.Listener) error {
	if m == nil {
		return errors.New("sftp: nil connection manager")
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		srv, err := m.NewServer(conn)
		if err != nil {
			// NewServer closes conn for lifecycle/construction failures.
			continue
		}

		go func(srv *Server) {
			_ = srv.Serve()
			_ = srv.Close()
		}(srv)
	}
}

// The following options are the ServerOption integration points.

// WithUsername records the authenticated principal supplied by the transport
// authentication layer (for example SSH ConnMetadata.User). The value is
// stored only on this Server.
func WithUsername(username string) ServerOption {
	return func(s *Server) error {
		s.lifecycle.setUsername(username)
		return nil
	}
}

// WithAuthenticated records a successful transport authentication result.
func WithAuthenticated(username string) ServerOption {
	return func(s *Server) error {
		s.lifecycle.setAuthenticated(username, true, nil)
		return nil
	}
}

// WithAuthenticationState records a complete authentication result.
func WithAuthenticationState(username string, authenticated bool, authErr error) ServerOption {
	return func(s *Server) error {
		s.lifecycle.setAuthenticated(username, authenticated, authErr)
		return nil
	}
}

// WithAuthenticator configures an in-process authenticator used by
// Server.Authenticate. Most deployments authenticate SSH before SFTP and can
// instead call SetAuthResult with the SSH result.
func WithAuthenticator(authenticator Authenticator) ServerOption {
	return func(s *Server) error {
		s.authenticator = authenticator
		return nil
	}
}

// WithAuth is an alias for WithAuthenticator.
func WithAuth(authenticator Authenticator) ServerOption {
	return WithAuthenticator(authenticator)
}

// WithAuthentication is an alias for WithAuthenticator.
func WithAuthentication(authenticator Authenticator) ServerOption {
	return WithAuthenticator(authenticator)
}

// WithIdleTimeout disconnects a connection after timeout without packet I/O.
// Zero disables idle timeout, which preserves the historical behavior.
func WithIdleTimeout(timeout time.Duration) ServerOption {
	return func(s *Server) error {
		if timeout < 0 {
			return errors.New("sftp: idle timeout must be greater than or equal to zero")
		}
		s.idleTimeout = timeout
		return nil
	}
}

// WithIdleConnectionTimeout is an alias for WithIdleTimeout.
func WithIdleConnectionTimeout(timeout time.Duration) ServerOption {
	return WithIdleTimeout(timeout)
}

// WithIdleTime is an alias for WithIdleTimeout.
func WithIdleTime(timeout time.Duration) ServerOption {
	return WithIdleTimeout(timeout)
}

// WithServerIdleTimeout is an alias for WithIdleTimeout.
func WithServerIdleTimeout(timeout time.Duration) ServerOption {
	return WithIdleTimeout(timeout)
}

// WithHandshakeTimeout limits the time waiting for the SFTP INIT/VERSION
// exchange. Zero disables a separate handshake timeout; WithIdleTimeout still
// applies during the handshake.
func WithHandshakeTimeout(timeout time.Duration) ServerOption {
	return func(s *Server) error {
		if timeout < 0 {
			return errors.New("sftp: handshake timeout must be greater than or equal to zero")
		}
		s.handshakeTimeout = timeout
		return nil
	}
}

// WithMaxConnections records a connection limit on the Server configuration.
// A limit is only enforced across connections when the option is passed to
// NewConnectionManager or when WithConnectionLimiter supplies a shared
// limiter.
func WithMaxConnections(maxConnections int) ServerOption {
	return func(s *Server) error {
		if maxConnections < 0 {
			return errors.New("sftp: max connections must be greater than or equal to zero")
		}
		s.maxConnections = maxConnections
		return nil
	}
}

// WithMaxConcurrentConnections is an alias for WithMaxConnections.
func WithMaxConcurrentConnections(maxConnections int) ServerOption {
	return WithMaxConnections(maxConnections)
}

// WithMaxConns is an alias for WithMaxConnections.
func WithMaxConns(maxConnections int) ServerOption {
	return WithMaxConnections(maxConnections)
}

// WithMaxOpenConnections is an alias for WithMaxConnections.
func WithMaxOpenConnections(maxConnections int) ServerOption {
	return WithMaxConnections(maxConnections)
}

// WithServerMaxConnections is an alias for WithMaxConnections.
func WithServerMaxConnections(maxConnections int) ServerOption {
	return WithMaxConnections(maxConnections)
}

// WithConnectionLimit is an alias for WithMaxConnections.
func WithConnectionLimit(maxConnections int) ServerOption {
	return WithMaxConnections(maxConnections)
}

// WithConnectionLimiter attaches a shared limiter to one Server.
func WithConnectionLimiter(limiter *ConnectionLimiter) ServerOption {
	return func(s *Server) error {
		if limiter == nil {
			return errors.New("sftp: connection limiter must not be nil")
		}
		s.limiter = limiter
		return nil
	}
}

// WithLimiter is an alias for WithConnectionLimiter.
func WithLimiter(limiter *ConnectionLimiter) ServerOption {
	return WithConnectionLimiter(limiter)
}

// WithConnectionManager attaches a shared manager. It is normally added by
// ConnectionManager.NewServer rather than called directly.
func WithConnectionManager(manager *ConnectionManager) ServerOption {
	return func(s *Server) error {
		if manager == nil {
			return errors.New("sftp: connection manager must not be nil")
		}
		s.manager = manager
		return nil
	}
}

// ConnectionState returns a concurrency-safe snapshot of this connection's
// handshake and authentication state.
func (s *Server) ConnectionState() ConnectionInfo {
	if s == nil || s.lifecycle == nil {
		return ConnectionInfo{Handshake: HandshakePending}
	}
	return s.lifecycle.snapshot()
}

// State is an alias for ConnectionState.
func (s *Server) State() ConnectionInfo {
	return s.ConnectionState()
}

// HandshakeState returns only the current handshake state.
func (s *Server) HandshakeState() HandshakeState {
	return s.ConnectionState().Handshake
}

// HandshakeStatus returns only the current handshake status.
func (s *Server) HandshakeStatus() HandshakeStatus {
	return s.HandshakeState()
}

// AuthResult returns the authentication result bound to this connection.
func (s *Server) AuthResult() AuthResult {
	state := s.ConnectionState()
	return AuthResult{
		Username:      state.Username,
		Authenticated: state.Authenticated && state.AuthenticationError == nil,
		Err:           state.AuthenticationError,
	}
}

// GetAuthResult returns the components of the authentication result.
func (s *Server) GetAuthResult() (username string, authenticated bool, err error) {
	result := s.AuthResult()
	return result.Username, result.Authenticated, result.Err
}

// Username returns the principal bound to this connection.
func (s *Server) Username() string {
	return s.ConnectionState().Username
}

// SetUsername binds a username to this connection only.
func (s *Server) SetUsername(username string) {
	s.lifecycle.setUsername(username)
}

// IsAuthenticated reports whether this connection's recorded auth result is
// successful.
func (s *Server) IsAuthenticated() bool {
	state := s.ConnectionState()
	return state.Authenticated && state.AuthenticationError == nil
}

// SetAuthenticated records a successful authentication result.
func (s *Server) SetAuthenticated(username string) {
	s.lifecycle.setAuthenticated(username, true, nil)
}

// Authenticate runs the configured Authenticator and immediately closes and
// cleans up the connection when authentication fails.
func (s *Server) Authenticate(info AuthInfo) error {
	if s.authenticator == nil {
		return ErrAuthenticatorRequired
	}
	err := s.authenticator.Authenticate(info)
	return s.SetAuthResult(info.Username, err)
}

// SetAuthResult records an already-performed authentication result. A non-nil
// err causes immediate close and resource cleanup.
func (s *Server) SetAuthResult(username string, err error) error {
	if err != nil {
		return s.RejectAuthentication(username, err)
	}
	s.lifecycle.setAuthenticated(username, true, nil)
	return nil
}

// RejectAuthentication records the failure, closes the transport, and releases
// open handles and buffers. It returns reason unchanged when non-nil.
func (s *Server) RejectAuthentication(username string, reason error) error {
	if reason == nil {
		reason = ErrAuthenticationFailed
	}
	s.lifecycle.setAuthenticated(username, false, reason)
	_ = s.Close()
	return reason
}

// touchActivity records local activity without changing the idle timer.
func (s *Server) touchActivity() {
	if s != nil && s.lifecycle != nil {
		s.lifecycle.touch()
	}
}
