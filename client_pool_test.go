package sftp

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// regularFileStat builds an SSH_FXP_ATTRS body describing a regular file of
// the given size.
func regularFileStat(id uint32, size uint64) []byte {
	b := marshalUint32(nil, id)
	b = marshalUint32(b, sshFileXferAttrSize|sshFileXferAttrPermissions)
	b = marshalUint64(b, size)
	return marshalUint32(b, 0o100644) // S_IFREG | 0644
}

// TestClientWriteToReusesBuffers checks that a download does not allocate a
// fresh buffer per packet and that every buffer is returned once the transfer
// finishes.
func TestClientWriteToReusesBuffers(t *testing.T) {
	const payloadSize = 8 << 10

	payload := bytes.Repeat([]byte("0123456789abcdef"), payloadSize/16)
	// The first reply is full-size, the second is short, which means EOF.
	chunks := [][]byte{payload, []byte("tail")}

	var (
		mu      sync.Mutex
		replyNo int
	)

	c := startScriptedClient(t, func(typ fxp, id uint32) (fxp, []byte, bool) {
		switch typ {
		case sshFxpStat:
			return sshFxpAttrs, regularFileStat(id, uint64(2*payloadSize)), true

		case sshFxpRead:
			mu.Lock()
			defer mu.Unlock()

			if replyNo >= len(chunks) {
				// A zero-length DATA reply would leave the sequential
				// reader spinning, so signal EOF explicitly.
				return sshFxpStatus, statusBody(marshalUint32(nil, id), sshFxEOF), true
			}

			body := marshalString(marshalUint32(nil, id), string(chunks[replyNo]))
			replyNo++
			return sshFxpData, body, true

		default:
			return sshFxpStatus, statusBody(marshalUint32(nil, id), sshFxOk), true
		}
	}, MaxPacket(payloadSize))
	defer c.Close()

	f := &File{c: c, path: "file", handle: "handle"}

	var out bytes.Buffer
	written, err := f.WriteTo(&out)
	require.NoError(t, err)

	want := append(append([]byte(nil), payload...), chunks[1]...)
	require.Equal(t, int64(len(want)), written)
	require.Equal(t, want, out.Bytes())

	stats := c.BufferPoolStats()
	require.Zero(t, stats.InUse, "transfer finished but still holds buffers")
	require.NotZero(t, stats.Borrowed)
	require.Equal(t, stats.Borrowed, stats.Returned)
}

// TestClientCloseReturnsBuffers checks that closing a client hands its cached
// buffers back to the shared pool and records the release.
func TestClientCloseReturnsBuffers(t *testing.T) {
	c := startScriptedClient(t, func(typ fxp, id uint32) (fxp, []byte, bool) {
		switch typ {
		case sshFxpStat:
			return sshFxpAttrs, regularFileStat(id, 4096), true
		case sshFxpRead:
			return sshFxpStatus, statusBody(marshalUint32(nil, id), sshFxEOF), true
		default:
			return sshFxpStatus, statusBody(marshalUint32(nil, id), sshFxOk), true
		}
	}, MaxPacket(4096))

	f := &File{c: c, path: "file", handle: "handle"}
	var out bytes.Buffer
	_, err := f.WriteTo(&out)
	require.NoError(t, err)

	before := GetBufferPoolStats()
	stats := c.BufferPoolStats()
	require.Zero(t, stats.InUse)
	require.NotZero(t, stats.Cached, "expected the connection to keep a buffer for reuse")

	require.NoError(t, c.Close())

	after := GetBufferPoolStats()
	require.Greater(t, after.Returned, before.Returned)
	require.Greater(t, after.ReleasedOnClose, before.ReleasedOnClose)
	require.Zero(t, c.BufferPoolStats().Cached)
	require.True(t, c.BufferPoolStats().Closed)
}

// TestClientDownloadWithSmallBufferLimit downloads a file whose size needs
// many packets through a client allowed only two transfer buffers, and checks
// the data arrives intact and nothing is left checked out.
func TestClientDownloadWithSmallBufferLimit(t *testing.T) {
	const (
		packetSize = 1024
		fileSize   = 64 * 1024
		limit      = 2
	)

	content := make([]byte, fileSize)
	for i := range content {
		content[i] = byte(i % 251)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "payload.bin")
	require.NoError(t, os.WriteFile(path, content, 0o600))

	c, cmd := testClientGoSvr(t, READONLY, NODELAY,
		MaxPacket(packetSize), BufferPoolLimit(limit))
	defer cmd.Wait()
	defer c.Close()

	f, err := c.Open(path)
	require.NoError(t, err)
	defer f.Close()

	var out bytes.Buffer
	written, err := f.WriteTo(&out)
	require.NoError(t, err)
	require.Equal(t, int64(fileSize), written)
	require.Equal(t, content, out.Bytes())

	stats := c.BufferPoolStats()
	require.Zero(t, stats.InUse, "download left buffers checked out")
	require.Equal(t, limit, stats.Limit)
	require.Equal(t, stats.Borrowed, stats.Returned)
}

// TestClientReadFromWithSmallBufferLimit is the upload counterpart: it checks
// the write path reuses one buffer and honours the connection's limit.
func TestClientReadFromWithSmallBufferLimit(t *testing.T) {
	const (
		packetSize = 1024
		fileSize   = 32 * 1024
		limit      = 1
	)

	content := make([]byte, fileSize)
	for i := range content {
		content[i] = byte(i % 241)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "upload.bin")

	c, cmd := testClientGoSvr(t, READWRITE, NODELAY,
		MaxPacket(packetSize), BufferPoolLimit(limit))
	defer cmd.Wait()
	defer c.Close()

	f, err := c.Create(path)
	require.NoError(t, err)

	written, err := f.ReadFrom(bytes.NewReader(content))
	require.NoError(t, err)
	require.Equal(t, int64(fileSize), written)
	require.NoError(t, f.Close())

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, content, got)

	stats := c.BufferPoolStats()
	require.Zero(t, stats.InUse, "upload left buffers checked out")
	require.Equal(t, stats.Borrowed, stats.Returned)
}

// TestClientDownloadAcrossFilesReusesBuffers checks that buffers cached by one
// download are reused by the next one on the same connection.
func TestClientDownloadAcrossFilesReusesBuffers(t *testing.T) {
	const packetSize = 4096

	content := bytes.Repeat([]byte("reuse-me"), 2048)

	dir := t.TempDir()
	for _, name := range []string{"a.bin", "b.bin"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), content, 0o600))
	}

	c, cmd := testClientGoSvr(t, READONLY, NODELAY, MaxPacket(packetSize))
	defer cmd.Wait()
	defer c.Close()

	download := func(name string) {
		f, err := c.Open(filepath.Join(dir, name))
		require.NoError(t, err)
		defer f.Close()

		var out bytes.Buffer
		_, err = f.WriteTo(&out)
		require.NoError(t, err)
		require.Equal(t, content, out.Bytes())
	}

	download("a.bin")
	first := c.BufferPoolStats()
	require.NotZero(t, first.Cached, "expected a buffer to be cached for reuse")

	sharedBefore := GetBufferPoolStats()
	download("b.bin")
	second := c.BufferPoolStats()
	sharedAfter := GetBufferPoolStats()

	require.Zero(t, second.InUse)

	// Buffers handed out from the connection's cache never touch the shared
	// pool, so the difference is how many of the second download's buffers
	// were reused from the first one.
	connBorrowed := second.Borrowed - first.Borrowed
	sharedBorrowed := sharedAfter.Borrowed - sharedBefore.Borrowed
	require.NotZero(t, connBorrowed)
	require.Less(t, sharedBorrowed, connBorrowed,
		"second download did not reuse any cached buffer")
}

// TestClientConcurrentDownloadsWithTinyBufferLimit checks that several
// downloads sharing a connection with a very small buffer allowance make
// progress together instead of waiting on each other's buffers.
func TestClientConcurrentDownloadsWithTinyBufferLimit(t *testing.T) {
	const (
		packetSize = 1024
		fileSize   = 48 * 1024
		limit      = 2
		files      = 4
	)

	dir := t.TempDir()

	contents := make([][]byte, files)
	for i := range contents {
		content := make([]byte, fileSize)
		for j := range content {
			content[j] = byte((i*37 + j) % 251)
		}
		contents[i] = content
		require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%d.bin", i)), content, 0o600))
	}

	c, cmd := testClientGoSvr(t, READONLY, NODELAY,
		MaxPacket(packetSize), BufferPoolLimit(limit))
	defer cmd.Wait()
	defer c.Close()

	done := make(chan error, files)
	for i := 0; i < files; i++ {
		go func(i int) {
			f, err := c.Open(filepath.Join(dir, fmt.Sprintf("f%d.bin", i)))
			if err != nil {
				done <- err
				return
			}
			defer f.Close()

			var out bytes.Buffer
			if _, err := f.WriteTo(&out); err != nil {
				done <- err
				return
			}
			if !bytes.Equal(out.Bytes(), contents[i]) {
				done <- fmt.Errorf("file %d: content mismatch", i)
				return
			}
			done <- nil
		}(i)
	}

	timeout := time.After(30 * time.Second)
	for i := 0; i < files; i++ {
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-timeout:
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, true)
			t.Fatalf("concurrent downloads stalled on the buffer limit; stats=%+v\n%s", c.BufferPoolStats(), buf[:n])
		}
	}

	stats := c.BufferPoolStats()
	require.Zero(t, stats.InUse)
	require.Equal(t, limit, stats.Limit)
}

// TestClientManySmallDownloadsLeaveNoBuffers borrows and returns buffers
// across many sequential small downloads and checks the connection ends with
// nothing in use and a bounded cache.
func TestClientManySmallDownloadsLeaveNoBuffers(t *testing.T) {
	const (
		fileSize  = 3 * 1024
		fileCount = 20
	)

	content := bytes.Repeat([]byte("small-file"), fileSize/10)

	dir := t.TempDir()
	for i := 0; i < fileCount; i++ {
		require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("s%d.bin", i)), content, 0o600))
	}

	c, cmd := testClientGoSvr(t, READONLY, NODELAY, MaxPacket(1024), BufferPoolLimit(4))
	defer cmd.Wait()
	defer c.Close()

	for i := 0; i < fileCount; i++ {
		f, err := c.Open(filepath.Join(dir, fmt.Sprintf("s%d.bin", i)))
		require.NoError(t, err)

		var out bytes.Buffer
		_, err = f.WriteTo(&out)
		require.NoError(t, err)
		require.Equal(t, content, out.Bytes())
		require.NoError(t, f.Close())
	}

	stats := c.BufferPoolStats()
	require.Zero(t, stats.InUse)
	require.Equal(t, stats.Borrowed, stats.Returned)
	require.LessOrEqual(t, stats.Cached, 4)
}
