package sftp

import (
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestBufferPoolRoundsUpToClass(t *testing.T) {
	pool := newBufferPool()

	cases := []struct {
		request int
		wantCap int
	}{
		{1, 4 << 10},
		{4 << 10, 4 << 10},
		{(4 << 10) + 1, 8 << 10},
		{32 << 10, 32 << 10},
		{100 << 10, 128 << 10},
		{4 << 20, 4 << 20},
	}

	for _, tc := range cases {
		buf := pool.get(tc.request)
		if len(buf.b) != tc.request {
			t.Errorf("get(%d): len = %d, want %d", tc.request, len(buf.b), tc.request)
		}
		if cap(buf.b) != tc.wantCap {
			t.Errorf("get(%d): cap = %d, want %d", tc.request, cap(buf.b), tc.wantCap)
		}
		pool.put(buf)
	}
}

func TestBufferPoolReusesBuffer(t *testing.T) {
	// Reuse is asserted at the connection tier: sync.Pool may drop its
	// contents at any GC, so the shared pool itself gives no such guarantee.
	conn := newConnBufPool(newBufferPool(), 4)
	lease := newBufferLease(conn)
	defer lease.release()

	first, err := lease.get(1000)
	if err != nil {
		t.Fatal(err)
	}
	firstKey := first.key()
	firstCap := cap(first.b)
	lease.put(first)

	second, err := lease.get(1000)
	if err != nil {
		t.Fatal(err)
	}
	if second.key() != firstKey {
		t.Fatal("connection did not reuse the returned buffer")
	}
	if cap(second.b) != firstCap {
		t.Errorf("reused buffer capacity = %d, want %d", cap(second.b), firstCap)
	}
}

func TestBufferPoolReturnResetsLengthAndClearsContents(t *testing.T) {
	pool := newBufferPool()

	buf := pool.get(64)
	for i := range buf.b {
		buf.b[i] = 0xAA
	}
	// Return a full-capacity view, the way a caller that grew the slice would.
	buf.b = buf.b[:cap(buf.b)]
	pool.put(buf)

	got := pool.get(64)
	for i, v := range got.b {
		if v != 0 {
			t.Fatalf("byte %d = %#x after reuse, want 0", i, v)
		}
	}

	// A pooled buffer must come back with the length the caller asked for.
	if len(got.b) != 64 {
		t.Errorf("len = %d, want 64", len(got.b))
	}
	pool.put(got)
}

func TestBufferPoolDropsForeignSlices(t *testing.T) {
	pool := newBufferPool()

	before := pool.stats()

	// An exactly-sized buffer is accepted.
	pool.put(&buffer{b: make([]byte, 4<<10)})
	if got := pool.stats().Discarded - before.Discarded; got != 0 {
		t.Errorf("discarded = %d after a class-sized return, want 0", got)
	}

	// A buffer that does not match a class is not retained.
	pool.put(&buffer{b: make([]byte, 1000)})
	if got := pool.stats().Discarded - before.Discarded; got != 1 {
		t.Errorf("discarded = %d after a foreign return, want 1", got)
	}
}

func TestBufferPoolOversizeIsNotPooled(t *testing.T) {
	pool := newBufferPool()

	buf := pool.get((4 << 20) + 1)
	if len(buf.b) != (4<<20)+1 {
		t.Fatalf("len = %d, want %d", len(buf.b), (4<<20)+1)
	}
	if class := pool.classForCap(cap(buf.b)); class != nil {
		t.Fatalf("oversize buffer matches class %d", class.size)
	}

	before := pool.stats()
	pool.put(buf)
	after := pool.stats()

	if after.Discarded != before.Discarded+1 {
		t.Errorf("discarded = %d, want %d", after.Discarded, before.Discarded+1)
	}
}

func TestConnectionBufferLimit(t *testing.T) {
	conn := newConnBufPool(newBufferPool(), 2)
	lease := newBufferLease(conn)

	first, err := lease.get(1024)
	if err != nil {
		t.Fatal(err)
	}
	second, err := lease.get(1024)
	if err != nil {
		t.Fatal(err)
	}
	if got := conn.inUse(); got != 2 {
		t.Fatalf("in use = %d, want 2", got)
	}

	// The third request must wait rather than exceed the limit.
	acquired := make(chan error, 1)
	go func() {
		_, err := lease.get(1024)
		acquired <- err
	}()

	select {
	case err := <-acquired:
		t.Fatalf("third buffer acquired without waiting: err = %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	// Returning one buffer lets the waiting request through.
	lease.put(first)
	select {
	case err := <-acquired:
		if err != nil {
			t.Fatalf("waiting request failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiting request did not proceed after a buffer was returned")
	}

	lease.put(second)
	lease.release()
	if got := conn.inUse(); got != 0 {
		t.Errorf("in use after release = %d, want 0", got)
	}
}

func TestConnectionBufferLimitNeverExceeded(t *testing.T) {
	const limit = 4

	conn := newConnBufPool(newBufferPool(), limit)

	var maxSeen int
	var mu sync.Mutex

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lease := newBufferLease(conn)
			defer lease.release()

			for j := 0; j < 50; j++ {
				b, err := lease.get(1024)
				if err != nil {
					t.Errorf("get: %v", err)
					return
				}

				mu.Lock()
				if inUse := conn.inUse(); inUse > maxSeen {
					maxSeen = inUse
				}
				mu.Unlock()

				lease.put(b)
			}
		}()
	}
	wg.Wait()

	if maxSeen > limit {
		t.Errorf("connection held %d buffers, limit is %d", maxSeen, limit)
	}
	if got := conn.inUse(); got != 0 {
		t.Errorf("in use after all leases released = %d, want 0", got)
	}
}

func TestConnectionCloseReleasesBuffers(t *testing.T) {
	conn := newConnBufPool(newBufferPool(), 8)
	lease := newBufferLease(conn)

	if _, err := lease.get(1024); err != nil {
		t.Fatal(err)
	}
	if _, err := lease.get(4096); err != nil {
		t.Fatal(err)
	}
	if got := conn.inUse(); got != 2 {
		t.Fatalf("in use = %d, want 2", got)
	}

	conn.close()

	stats := conn.stats()
	if !stats.Closed {
		t.Error("connection pool not marked closed")
	}
	if stats.InUse != 0 {
		t.Errorf("in use = %d after close, want 0", stats.InUse)
	}

	// A lease that outlives the connection returns its buffers to the shared
	// pool as it unwinds.
	lease.release()
	if got := conn.inUse(); got != 0 {
		t.Errorf("in use after late lease release = %d, want 0", got)
	}
}

func TestConnectionCloseReturnsCachedBuffersToSharedPool(t *testing.T) {
	pool := newBufferPool()
	conn := newConnBufPool(pool, 8)

	lease := newBufferLease(conn)
	b, err := lease.get(1024)
	if err != nil {
		t.Fatal(err)
	}

	before := pool.stats()
	lease.put(b)
	if got := conn.stats().Cached; got != 1 {
		t.Fatalf("cached = %d, want 1", got)
	}
	if after := pool.stats(); after.Returned != before.Returned {
		t.Errorf("buffer went to the shared pool while the connection was open")
	}

	conn.close()

	after := pool.stats()
	if after.Returned != before.Returned+1 {
		t.Errorf("shared pool returned = %d, want cached buffer flushed (%d)",
			after.Returned, before.Returned+1)
	}
	if got := after.ReleasedOnClose; got == before.ReleasedOnClose {
		t.Error("shared pool did not record a close-released buffer")
	}
	if got := conn.stats().Cached; got != 0 {
		t.Errorf("cached = %d after close, want 0", got)
	}
}

func TestConnectionCloseUnblocksWaiters(t *testing.T) {
	conn := newConnBufPool(newBufferPool(), 1)
	lease := newBufferLease(conn)
	defer lease.release()

	if _, err := lease.get(1024); err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		other := newBufferLease(conn)
		defer other.release()
		_, err := other.get(1024)
		errCh <- err
	}()

	select {
	case err := <-errCh:
		t.Fatalf("waiter returned early: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	conn.close()

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrBufferPoolClosed) {
			t.Fatalf("waiter error = %v, want %v", err, ErrBufferPoolClosed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter was not woken by connection close")
	}
}

func TestLeaseReleaseReturnsBuffers(t *testing.T) {
	conn := newConnBufPool(newBufferPool(), 4)
	lease := newBufferLease(conn)

	for i := 0; i < 4; i++ {
		if _, err := lease.get(1024); err != nil {
			t.Fatal(err)
		}
	}

	// release must return everything without individual puts, which is what
	// makes an early return on an error path safe.
	lease.release()

	if got := conn.inUse(); got != 0 {
		t.Errorf("in use after release = %d, want 0", got)
	}
}

func TestLeaseDoublePutIsIgnored(t *testing.T) {
	pool := newBufferPool()
	conn := newConnBufPool(pool, 4)
	lease := newBufferLease(conn)

	b, err := lease.get(1024)
	if err != nil {
		t.Fatal(err)
	}

	lease.put(b)
	lease.put(b) // must not free a slot twice or pool the buffer twice

	if got := conn.inUse(); got != 0 {
		t.Errorf("in use = %d, want 0", got)
	}
	if got := conn.stats().InUse; got != 0 {
		t.Errorf("stats in use = %d, want 0", got)
	}
}

func TestBufferPoolStatsAccountBorrowAndReturn(t *testing.T) {
	pool := newBufferPool()

	before := pool.stats()

	buf := pool.get(32 << 10)
	mid := pool.stats()
	if mid.Borrowed != before.Borrowed+1 {
		t.Errorf("borrowed = %d, want %d", mid.Borrowed, before.Borrowed+1)
	}

	pool.put(buf)
	after := pool.stats()
	if after.Returned != before.Returned+1 {
		t.Errorf("returned = %d, want %d", after.Returned, before.Returned+1)
	}
	if after.InUse != before.InUse {
		t.Errorf("in use = %d, want %d", after.InUse, before.InUse)
	}
}

// TestBufferPoolConcurrentReuse makes sure concurrent borrowers never see each
// other's data: each goroutine fills its buffer with its own byte, returns it,
// and checks that every later buffer starts out zeroed.
func TestBufferPoolConcurrentReuse(t *testing.T) {
	conn := newConnBufPool(newBufferPool(), 16)

	const workers = 64
	var wg sync.WaitGroup
	errCh := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			lease := newBufferLease(conn)
			defer lease.release()

			want := byte(id + 1)
			for j := 0; j < 100; j++ {
				buf, err := lease.get(1024)
				if err != nil {
					errCh <- err
					return
				}

				for _, v := range buf.b {
					if v != 0 {
						errCh <- errors.New("buffer retained data from a previous request")
						return
					}
				}
				for k := range buf.b {
					buf.b[k] = want
				}

				lease.put(buf)
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}

	if got := conn.inUse(); got != 0 {
		t.Errorf("in use = %d, want 0", got)
	}
}

func TestBufferPoolZeroSizePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("get(0) did not panic")
		}
	}()
	newBufferPool().get(0)
}

func BenchmarkBufferPoolGetPut(b *testing.B) {
	conn := newConnBufPool(newBufferPool(), 64)
	lease := newBufferLease(conn)
	defer lease.release()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf, err := lease.get(32 << 10)
		if err != nil {
			b.Fatal(err)
		}
		lease.put(buf)
	}
}

func BenchmarkBufferPoolGetPutParallel(b *testing.B) {
	conn := newConnBufPool(newBufferPool(), 64)

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		lease := newBufferLease(conn)
		defer lease.release()

		for pb.Next() {
			buf, err := lease.get(32 << 10)
			if err != nil {
				b.Fatal(err)
			}
			lease.put(buf)
		}
	})
}

// TestBufferLeaseWithNilConn exercises the path used by callers that do not
// have a connection, which must still work through the shared pool.
func TestBufferLeaseWithNilConn(t *testing.T) {
	lease := newBufferLease(nil)

	buf, err := lease.get(1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(buf.b) != 1024 {
		t.Fatalf("len = %d, want 1024", len(buf.b))
	}

	lease.put(buf)
}

func TestConnBufferPoolStatsCounts(t *testing.T) {
	conn := newConnBufPool(newBufferPool(), 4)
	lease := newBufferLease(conn)

	buf, err := lease.get(1024)
	if err != nil {
		t.Fatal(err)
	}

	s := conn.stats()
	if s.Borrowed != 1 {
		t.Errorf("borrowed = %d, want 1", s.Borrowed)
	}
	if s.InUse != 1 {
		t.Errorf("in use = %d, want 1", s.InUse)
	}

	lease.put(buf)
	s = conn.stats()
	if s.Returned != 1 {
		t.Errorf("returned = %d, want 1", s.Returned)
	}
	if s.InUse != 0 {
		t.Errorf("in use = %d, want 0", s.InUse)
	}
	if s.Cached != 1 {
		t.Errorf("cached = %d, want 1", s.Cached)
	}

	conn.close()
	s = conn.stats()
	if s.ReleasedOnClose != 1 {
		t.Errorf("released on close = %d, want 1", s.ReleasedOnClose)
	}
}

// TestBufferPoolNoGoroutineLeak verifies waiters do not stay blocked after a
// connection closes.
func TestBufferPoolNoGoroutineLeak(t *testing.T) {
	conn := newConnBufPool(newBufferPool(), 1)

	lease := newBufferLease(conn)
	if _, err := lease.get(1024); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l := newBufferLease(conn)
			defer l.release()
			_, _ = l.get(1024)
		}()
	}

	conn.close()
	lease.release()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("waiters still blocked after close; %d goroutines running", runtime.NumGoroutine())
	}
}

// TestConnectionCloseDoesNotRecycleCheckedOutBuffers makes sure a buffer that
// a transfer still holds when the connection closes is not handed to another
// request, which would let two writers share one backing array. The buffer is
// accounted as returned at close and goes back to the pool only when the
// transfer's lease unwinds.
func TestConnectionCloseDoesNotRecycleCheckedOutBuffers(t *testing.T) {
	pool := newBufferPool()
	conn := newConnBufPool(pool, 4)
	lease := newBufferLease(conn)

	buf, err := lease.get(4096)
	if err != nil {
		t.Fatal(err)
	}
	key := buf.key()

	before := pool.stats()
	conn.close()
	after := pool.stats()

	// The connection stops accounting for it...
	if got := conn.stats().InUse; got != 0 {
		t.Errorf("connection in use = %d after close, want 0", got)
	}
	if got := conn.stats().ReleasedOnClose; got == 0 {
		t.Error("connection did not record the close release")
	}

	// ...but it is not available to other requests yet.
	if got := after.Returned - before.Returned; got != 0 {
		t.Errorf("shared pool returned delta = %d, want 0 while the buffer is still in use", got)
	}
	for i := 0; i < 64; i++ {
		other := pool.get(4096)
		if other.key() == key {
			t.Fatal("pool re-handed a buffer still held by a closing transfer")
		}
		pool.put(other)
	}

	// Once the transfer unwinds, its buffer is pooled exactly once.
	beforeUnwind := pool.stats()
	lease.release()
	afterUnwind := pool.stats()
	if got := afterUnwind.Returned - beforeUnwind.Returned; got != 1 {
		t.Errorf("returned delta after unwinding = %d, want 1", got)
	}

	// A second release must not count it again.
	lease.release()
	if got := pool.stats().Returned; got != afterUnwind.Returned {
		t.Errorf("returned = %d after a duplicate release, want %d", got, afterUnwind.Returned)
	}
}

// TestBufferPoolPublicStatsBorrowAndReturn drives the exported statistics
// through a real connection and checks the borrow and return counts are
// visible outside the package.
func TestBufferPoolPublicStatsBorrowAndReturn(t *testing.T) {
	conn := newConnBufPool(defaultBufferPool, 2)
	lease := newBufferLease(conn)

	before := GetBufferPoolStats()

	buf, err := lease.get(32 << 10)
	if err != nil {
		t.Fatal(err)
	}
	lease.put(buf)

	conn.close()

	after := GetBufferPoolStats()
	if after.Borrowed < before.Borrowed+1 {
		t.Errorf("borrowed = %d, want at least %d", after.Borrowed, before.Borrowed+1)
	}
	if after.Returned < before.Returned+1 {
		t.Errorf("returned = %d, want at least %d", after.Returned, before.Returned+1)
	}
	if after.ReleasedOnClose < before.ReleasedOnClose+1 {
		t.Errorf("released on close = %d, want at least %d",
			after.ReleasedOnClose, before.ReleasedOnClose+1)
	}

	// The class that serves 32 KiB reports the traffic it saw.
	var found bool
	for _, class := range after.Classes {
		if class.Size != 32<<10 {
			continue
		}
		found = true
		if class.Borrowed == 0 || class.Returned == 0 {
			t.Errorf("class %d: borrowed = %d, returned = %d, want both non-zero",
				class.Size, class.Borrowed, class.Returned)
		}
	}
	if !found {
		t.Fatalf("no 32 KiB class in stats: %+v", after.Classes)
	}
}
