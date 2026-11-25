package sftp

import (
	"errors"
	"sync"
	"sync/atomic"
)

var (
	// ErrBufferPoolClosed is returned when a transfer buffer is requested
	// from a connection whose buffer pool has already been closed, for
	// example because the connection was closed while a transfer was
	// waiting for buffer capacity.
	ErrBufferPoolClosed = errors.New("sftp: connection buffer pool closed")

	// errBufferPoolCanceled is returned internally when a transfer aborts
	// while waiting for buffer capacity.
	errBufferPoolCanceled = errors.New("sftp: buffer wait canceled")
)

// bufferClassSizes lists the buffer sizes managed by the shared transfer
// buffer pool. Requests are rounded up to the smallest class that fits, so a
// buffer obtained for one request can serve any later request in that class
// without reallocation.
//
// Keeping each class at a fixed capacity also lets the pool reject slices that
// a caller has grown, instead of retaining arbitrarily large backing arrays.
var bufferClassSizes = [...]int{
	4 << 10,
	8 << 10,
	16 << 10,
	32 << 10,
	64 << 10,
	128 << 10,
	256 << 10,
	512 << 10,
	1 << 20,
	2 << 20,
	4 << 20,
}

// defaultMaxBuffersPerConnection bounds how many transfer buffers a single
// connection may hold at once, counting both buffers in use and buffers kept
// for reuse. The limit is a buffer count rather than a byte budget so it is
// cheap to enforce; at the default 32 KiB packet size it caps a connection at
// about 8 MiB of transfer buffers.
const defaultMaxBuffersPerConnection = 256

// defaultConnBufferCache bounds how many idle buffers a connection keeps for
// immediate reuse. It is smaller than the overall limit so that long-lived
// connections do not sit on a full working set of memory between transfers;
// anything above this goes back to the shared pool, where other connections
// can use it.
const defaultConnBufferCache = 16

// bufferClass is one size class of the shared transfer buffer pool.
//
// Free buffers live in a sync.Pool, so the common path is per-P and does not
// take a process-wide lock. That matters because every connection in the
// process borrows from these same classes.
type bufferClass struct {
	size int
	// free holds *buffer, not []byte: storing a slice header in an interface
	// boxes it and allocates on every get and put, which would defeat the
	// point of pooling.
	free sync.Pool

	borrowed  atomic.Uint64
	returned  atomic.Uint64
	allocated atomic.Uint64
}

// buffer is the handle a pooled transfer buffer travels in. Keeping the slice
// behind a pointer means the shared pool never boxes a slice header.
type buffer struct {
	b []byte
}

// key identifies the buffer by the address of its backing array. Pool buffers
// always start at the beginning of their array, so a length-only reslice keeps
// the same key.
func (b *buffer) key() *byte {
	if cap(b.b) == 0 {
		return nil
	}
	return &b.b[:cap(b.b)][0]
}

// bufferPool is the process-wide, size-classed pool of transfer buffers. It is
// the backing store for every connection's local cache.
//
// Buffers are handed out with the requested length and the capacity of their
// size class. Returning a buffer resets its length to zero while keeping the
// capacity, so the backing array is reused instead of being reallocated and a
// later request cannot observe the data a previous one left behind.
type bufferPool struct {
	classes []*bufferClass

	borrowed        atomic.Uint64
	returned        atomic.Uint64
	allocated       atomic.Uint64
	discarded       atomic.Uint64
	releasedOnClose atomic.Uint64
}

func newBufferPool() *bufferPool {
	p := &bufferPool{classes: make([]*bufferClass, len(bufferClassSizes))}
	for i, size := range bufferClassSizes {
		p.classes[i] = &bufferClass{size: size}
	}
	return p
}

// defaultBufferPool backs the transfer buffers of every connection.
var defaultBufferPool = newBufferPool()

// classFor returns the smallest class that can hold n bytes, or nil when n
// exceeds every class. Oversized requests are allocated directly and not
// pooled, which keeps memory retained by the pool bounded.
func (p *bufferPool) classFor(n int) *bufferClass {
	for _, c := range p.classes {
		if n <= c.size {
			return c
		}
	}
	return nil
}

// classIndexFor returns the index of the smallest class that can hold n
// bytes, or -1 when n exceeds every class.
func (p *bufferPool) classIndexFor(n int) int {
	for i, c := range p.classes {
		if n <= c.size {
			return i
		}
	}
	return -1
}

// classIndexForCap returns the index of the class matching capacity n
// exactly, or -1. Only exact matches are pooled: a slice resliced to a
// different capacity must not be filed under a class whose buffers are all n
// bytes long.
func (p *bufferPool) classIndexForCap(n int) int {
	for i, c := range p.classes {
		if n == c.size {
			return i
		}
	}
	return -1
}

// classForCap returns the class matching capacity n exactly, or nil. Only
// exact matches are pooled: a slice resliced to a different capacity must not
// be filed under a class whose buffers are all n bytes long.
func (p *bufferPool) classForCap(n int) *bufferClass {
	for _, c := range p.classes {
		if n == c.size {
			return c
		}
	}
	return nil
}

// get returns a buffer of at least n bytes. The returned slice has length n;
// its contents are unspecified, so callers must write everything they read.
func (p *bufferPool) get(n int) *buffer {
	if n <= 0 {
		panic("sftp: transfer buffer length must be greater than zero")
	}

	c := p.classFor(n)
	if c == nil {
		p.borrowed.Add(1)
		p.allocated.Add(1)
		return &buffer{b: make([]byte, n)}
	}

	p.borrowed.Add(1)
	c.borrowed.Add(1)

	if buf, ok := c.free.Get().(*buffer); ok && cap(buf.b) >= c.size {
		buf.b = buf.b[:n]
		return buf
	}

	p.allocated.Add(1)
	c.allocated.Add(1)
	return &buffer{b: make([]byte, c.size)[:n]}
}

// put clears b and returns it to its size class, keeping the capacity.
func (p *bufferPool) put(b *buffer) {
	p.putBuffer(b, false)
}

// forcePut returns b on behalf of a connection that is closing, counting it as
// a buffer released by connection close.
func (p *bufferPool) forcePut(b *buffer) {
	p.putBuffer(b, true)
}

func (p *bufferPool) putBuffer(buf *buffer, onClose bool) {
	if buf == nil {
		return
	}

	p.returned.Add(1)
	if onClose {
		p.releasedOnClose.Add(1)
	}

	c := p.classForCap(cap(buf.b))
	if c == nil {
		p.discarded.Add(1)
		return
	}

	// Reset the length and drop the old contents while keeping the capacity.
	// The whole capacity is cleared, not only the length, so no byte from the
	// previous request can be observed through the buffer, however it is
	// resliced.
	b := buf.b[:cap(buf.b)]
	clear(b)
	buf.b = b[:0]

	c.returned.Add(1)
	c.free.Put(buf)
}

// BufferClassStats holds the lifetime counters of one buffer size class.
type BufferClassStats struct {
	// Size is the capacity, in bytes, of buffers in this class.
	Size int
	// Borrowed is the number of buffers handed out from this class.
	Borrowed uint64
	// Returned is the number of buffers of this class accepted back.
	Returned uint64
	// Allocated is the number of times no free buffer was available and a
	// new backing array had to be allocated.
	Allocated uint64
}

// BufferPoolStats is a snapshot of the shared transfer buffer pool counters.
type BufferPoolStats struct {
	// Borrowed is the number of buffers handed out by the pool.
	Borrowed uint64
	// Returned is the number of buffers given back to the pool.
	Returned uint64
	// InUse is Borrowed minus Returned: buffers held by connections.
	InUse uint64
	// Allocated is the number of new backing arrays the pool had to create.
	Allocated uint64
	// Discarded is the number of returned buffers the pool did not keep,
	// because their capacity did not match a size class.
	Discarded uint64
	// ReleasedOnClose is the number of buffers flushed back to the shared
	// pool because their connection closed.
	ReleasedOnClose uint64
	// Classes holds per-size-class counters, ordered by increasing size.
	Classes []BufferClassStats
}

// GetBufferPoolStats returns a snapshot of the shared transfer buffer pool.
// Borrowed and Returned count every buffer handed out and given back, so InUse
// shows how many transfer buffers connections are holding right now.
func GetBufferPoolStats() BufferPoolStats {
	return defaultBufferPool.stats()
}

func (p *bufferPool) stats() BufferPoolStats {
	borrowed := p.borrowed.Load()
	returned := p.returned.Load()

	s := BufferPoolStats{
		Borrowed:        borrowed,
		Returned:        returned,
		Allocated:       p.allocated.Load(),
		Discarded:       p.discarded.Load(),
		ReleasedOnClose: p.releasedOnClose.Load(),
		Classes:         make([]BufferClassStats, len(p.classes)),
	}
	if borrowed > returned {
		s.InUse = borrowed - returned
	}

	for i, c := range p.classes {
		s.Classes[i] = BufferClassStats{
			Size:      c.size,
			Borrowed:  c.borrowed.Load(),
			Returned:  c.returned.Load(),
			Allocated: c.allocated.Load(),
		}
	}

	return s
}

// ConnBufferPoolStats is a snapshot of one connection's transfer buffer usage.
type ConnBufferPoolStats struct {
	// Limit is the maximum number of buffers the connection may hold.
	Limit int
	// Borrowed is the number of buffers handed to transfers on the connection.
	Borrowed uint64
	// Returned is the number of buffers given back by transfers.
	Returned uint64
	// InUse is the number of buffers currently checked out to transfers.
	InUse uint64
	// Cached is the number of buffers held for reuse by the connection.
	Cached int
	// ReleasedOnClose is the number of buffers returned to the shared pool
	// because the connection closed.
	ReleasedOnClose uint64
	// Closed reports whether the connection's pool has been closed.
	Closed bool
}

// connBufPool is the tier in front of the shared pool for one connection. It
// keeps a small cache of buffers for reuse, enforces the per-connection limit,
// tracks every buffer under the connection's name, and hands them all back to
// the shared pool when the connection closes.
//
// The limit bounds how many buffers the connection holds at once: buffers
// checked out by transfers plus idle buffers kept for reuse. A request that
// would exceed it waits until another is returned, or fails with
// ErrBufferPoolClosed if the connection closes meanwhile.
//
// Transfers never wait for a buffer while blocking the consumer that would
// return one: the concurrent read path takes its buffers in chunk order before
// handing chunks to workers, so the ordered consumer always has the chunk it
// needs and can return buffers. Waiting on the limit therefore cannot produce
// a cycle between transfers.
//
// Accounting uses a per-connection mutex only; goroutines on different
// connections never contend with each other, and the shared pool's fast path
// is lock-free.
type connBufPool struct {
	pool       *bufferPool
	max        int
	cacheLimit int

	mu       sync.Mutex
	cached   [][]*buffer // idle buffers kept for reuse, indexed like pool.classes
	nCached  int
	held     int // buffers checked out by transfers
	pending  int // buffers being allocated, already counted against the limit
	waiters  int // transfers blocked waiting for capacity
	borrowed uint64
	returned uint64
	onClose  uint64
	isClosed bool

	notify chan struct{} // closed and replaced whenever capacity is freed
	closed chan struct{} // closed once when the connection closes

	closeOnce sync.Once
}

func newConnBufPool(pool *bufferPool, max int) *connBufPool {
	if pool == nil {
		pool = defaultBufferPool
	}
	if max <= 0 {
		max = defaultMaxBuffersPerConnection
	}

	cacheLimit := defaultConnBufferCache
	if cacheLimit > max {
		cacheLimit = max
	}

	return &connBufPool{
		pool:       pool,
		max:        max,
		cacheLimit: cacheLimit,
		cached:     make([][]*buffer, len(bufferClassSizes)),
		notify:     make(chan struct{}),
		closed:     make(chan struct{}),
	}
}

// bufKey identifies a buffer by the address of its backing array. Pool
// buffers always start at the beginning of their array, so a length-only
// reslice keeps the same key.
func bufKey(b []byte) *byte {
	if cap(b) == 0 {
		return nil
	}
	return &b[:cap(b)][0]
}

// broadcastLocked wakes every goroutine waiting for capacity. The caller must
// hold c.mu.
func (c *connBufPool) broadcastLocked() {
	close(c.notify)
	c.notify = make(chan struct{})
}

// wakeLocked wakes waiters only if there are any. Replacing the notification
// channel allocates, so the no-waiter path (every return when the connection
// is not contended) must not pay for it. The caller must hold c.mu.
func (c *connBufPool) wakeLocked() {
	if c.waiters > 0 {
		c.broadcastLocked()
	}
}

// takeCachedLocked pops an idle buffer of the class that serves n, if any.
func (c *connBufPool) takeCachedLocked(n int) *buffer {
	idx := c.pool.classIndexFor(n)
	if idx < 0 {
		return nil
	}
	free := c.cached[idx]
	if len(free) == 0 {
		return nil
	}

	buf := free[len(free)-1]
	c.cached[idx] = free[:len(free)-1]
	c.nCached--
	if cap(buf.b) >= n {
		buf.b = buf.b[:n]
	}
	return buf
}

// evictCachedLocked pops one idle buffer of any class so its slot can be used
// for a different size. It returns nil when nothing is cached.
func (c *connBufPool) evictCachedLocked() *buffer {
	for idx, free := range c.cached {
		if len(free) == 0 {
			continue
		}

		buf := free[len(free)-1]
		c.cached[idx] = free[:len(free)-1]
		c.nCached--
		return buf
	}
	return nil
}

// acquire hands out a buffer of at least n bytes and records it under the
// connection's name. It waits while the connection is at its limit, returning
// ErrBufferPoolClosed if the connection closes first and
// errBufferPoolCanceled if cancel is closed.
func (c *connBufPool) acquire(n int, cancel <-chan struct{}) (*buffer, error) {
	for {
		c.mu.Lock()
		if c.isClosed {
			c.mu.Unlock()
			return nil, ErrBufferPoolClosed
		}

		if buf := c.takeCachedLocked(n); buf != nil {
			c.held++
			c.borrowed++
			c.mu.Unlock()
			return buf, nil
		}

		if c.held+c.nCached+c.pending < c.max {
			// Claim the slot before allocating so concurrent borrowers cannot
			// all observe free capacity and overshoot the limit.
			c.pending++
			c.mu.Unlock()

			buf := c.pool.get(n)

			c.mu.Lock()
			c.pending--
			if c.isClosed {
				// Lost a race with close; do not register it under a closed
				// connection.
				c.mu.Unlock()
				c.pool.put(buf)
				return nil, ErrBufferPoolClosed
			}
			c.held++
			c.borrowed++
			c.mu.Unlock()

			return buf, nil
		}

		if evicted := c.evictCachedLocked(); evicted != nil {
			// The connection is full but holds idle buffers of another size
			// class. Free one rather than waiting for one of the right size.
			c.mu.Unlock()
			c.pool.put(evicted)
			continue
		}

		wait := c.notify
		c.waiters++
		c.mu.Unlock()

		select {
		case <-wait:
			c.waiterDone()
		case <-c.closed:
			c.waiterDone()
			return nil, ErrBufferPoolClosed
		case <-cancel:
			c.waiterDone()
			return nil, errBufferPoolCanceled
		}
	}
}

// waiterDone records that a blocked transfer stopped waiting.
func (c *connBufPool) waiterDone() {
	c.mu.Lock()
	c.waiters--
	if c.waiters < 0 {
		c.waiters = 0
	}
	c.mu.Unlock()
}

// release takes back a buffer from a transfer. While the connection is open
// and its cache has room, the buffer is kept for reuse; otherwise it goes back
// to the shared pool. Either way the slot it occupied is free again, so a
// waiting request is woken.
//
// A release after close is ignored: close already accounted for the buffer as
// returned and deliberately did not pool it.
func (c *connBufPool) release(buf *buffer) {
	if buf == nil {
		return
	}

	idx := c.pool.classIndexForCap(cap(buf.b))

	c.mu.Lock()
	if c.isClosed {
		// close already settled the connection's accounting for this buffer
		// and deliberately left it out of the shared pool, because the
		// transfer was still using it. The transfer is done with it now, so
		// it is safe to pool.
		c.mu.Unlock()
		c.pool.forcePut(buf)
		return
	}
	c.held--
	if c.held < 0 {
		c.held = 0
	}
	c.returned++

	// A transfer is waiting for capacity: keep no buffer back for reuse, so
	// the slot is actually handed over instead of sitting idle in the cache.
	if idx >= 0 && c.nCached < c.cacheLimit && c.waiters == 0 {
		// Reset the length and drop stale contents before caching.
		b := buf.b[:cap(buf.b)]
		clear(b)
		buf.b = b[:0]

		c.cached[idx] = append(c.cached[idx], buf)
		c.nCached++
		c.wakeLocked()
		c.mu.Unlock()
		return
	}

	c.wakeLocked()
	c.mu.Unlock()
	c.pool.put(buf)
}

// close wakes every waiter and returns the connection's buffers to the shared
// pool. Idle cached buffers go back immediately. Buffers checked out by a
// transfer are still being written to, so they are handed back by that
// transfer's lease as it unwinds; pooling them now would let another request
// overwrite them mid-transfer. Either way the connection stops accounting for
// them at close, so its counters show nothing in use.
//
// It is safe to call more than once.
func (c *connBufPool) close() {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.isClosed = true
		c.pending = 0
		c.waiters = 0

		cached := make([]*buffer, 0, c.nCached)
		for _, free := range c.cached {
			cached = append(cached, free...)
		}
		c.cached = make([][]*buffer, len(bufferClassSizes))
		c.nCached = 0

		// Buffers checked out by transfers are still in use, so they are not
		// pooled here; each transfer returns its own as it unwinds (see
		// release). They are accounted as returned now, because the
		// connection no longer owns them.
		reclaimed := c.held
		c.held = 0
		c.returned += uint64(reclaimed)
		c.onClose += uint64(len(cached) + reclaimed)

		c.broadcastLocked()
		c.mu.Unlock()

		// Waiters select on closed, so closing it releases them with
		// ErrBufferPoolClosed.
		close(c.closed)

		for _, b := range cached {
			c.pool.forcePut(b)
		}
	})
}

// inUse reports how many buffers transfers currently hold.
func (c *connBufPool) inUse() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.held
}

// limit reports the connection's buffer limit.
func (c *connBufPool) limit() int {
	if c == nil {
		return 0
	}
	return c.max
}

// stats returns a snapshot of the connection's counters.
func (c *connBufPool) stats() ConnBufferPoolStats {
	if c == nil {
		return ConnBufferPoolStats{}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	return ConnBufferPoolStats{
		Limit:           c.max,
		Borrowed:        c.borrowed,
		Returned:        c.returned,
		InUse:           uint64(c.held),
		Cached:          c.nCached,
		ReleasedOnClose: c.onClose,
		Closed:          c.isClosed,
	}
}

// bufferLease is one transfer's claim on a connection's buffers. It records
// every buffer the transfer checked out so ending the lease returns them all,
// which keeps error paths from leaking buffers even if they skip individual
// puts. A nil connection means the transfer is only accounted for by the
// shared pool.
//
// A lease is safe for concurrent use by the goroutines of a single transfer.
type bufferLease struct {
	conn *connBufPool

	mu   sync.Mutex
	held map[*buffer]struct{}
}

// newBufferLease starts a lease against c.
func newBufferLease(c *connBufPool) *bufferLease {
	return &bufferLease{conn: c, held: make(map[*buffer]struct{})}
}

// get returns a buffer of at least n bytes, waiting for connection capacity if
// the limit is reached. Callers that only need the bytes can use getBytes.
func (l *bufferLease) get(n int) (*buffer, error) {
	return l.getWithCancel(n, nil)
}

// getWithCancel behaves like get but stops waiting when cancel is closed,
// returning errBufferPoolCanceled.
func (l *bufferLease) getWithCancel(n int, cancel <-chan struct{}) (*buffer, error) {
	var (
		buf *buffer
		err error
	)
	if l == nil || l.conn == nil {
		buf = defaultBufferPool.get(n)
	} else {
		buf, err = l.conn.acquire(n, cancel)
		if err != nil {
			return nil, err
		}
	}

	l.mu.Lock()
	l.held[buf] = struct{}{}
	l.mu.Unlock()

	return buf, nil
}

// put returns one buffer. Buffers already returned (by put, release, or
// connection close) are ignored, so a buffer is never pooled twice.
func (l *bufferLease) put(buf *buffer) {
	if buf == nil {
		return
	}
	if l == nil || l.conn == nil {
		defaultBufferPool.put(buf)
		return
	}

	l.mu.Lock()
	_, ok := l.held[buf]
	if ok {
		delete(l.held, buf)
	}
	l.mu.Unlock()

	if !ok {
		return
	}

	l.conn.release(buf)
}

// release returns every buffer the lease still holds. Callers should defer it
// at the start of a transfer so error paths cannot leak buffers.
func (l *bufferLease) release() {
	if l == nil {
		return
	}

	l.mu.Lock()
	held := l.held
	l.held = make(map[*buffer]struct{})
	l.mu.Unlock()

	for buf := range held {
		if l.conn == nil {
			defaultBufferPool.put(buf)
			continue
		}
		l.conn.release(buf)
	}
}

type resChanPool chan chan result

func newResChanPool(depth int) resChanPool {
	return make(chan chan result, depth)
}

func (p resChanPool) Get() chan result {
	select {
	case ch := <-p:
		return ch
	default:
		return make(chan result, 1)
	}
}

func (p resChanPool) Put(ch chan result) {
	select {
	case p <- ch:
	default:
	}
}
