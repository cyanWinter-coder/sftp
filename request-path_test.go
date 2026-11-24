package sftp

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCleanContainedPath(t *testing.T) {
	for name, tc := range map[string]struct {
		base string
		in   string
		want string
	}{
		"absolute path":           {"/", "/a/b", "/a/b"},
		"relative path":           {"/start", "a/b", "/start/a/b"},
		"parent inside root":      {"/", "/a/../b", "/b"},
		"parent to root":          {"/", "/a/..", "/"},
		"relative parent in root": {"/start", "../b", "/b"},
		"root itself":             {"/", "/", "/"},
		"empty input":             {"/start", "", "/start"},
		"start dir relative root": {"/start", ".", "/start"},
		"redundant separators":    {"/", "/a//b/", "/a/b"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := cleanContainedPath(tc.base, tc.in)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	// Any traversal that climbs past the virtual root is rejected before
	// cleaning, even though cleaning would have clamped it back to the root.
	for _, in := range []string{
		"/..",
		"/../etc/passwd",
		"/a/../../etc/passwd",
		"/start/../../escape",
	} {
		t.Run("escape "+in, func(t *testing.T) {
			_, err := cleanContainedPath("/start", in)
			require.Error(t, err)
			assert.True(t, errors.Is(err, os.ErrPermission), "expected permission error, got %v", err)
		})
	}
}

func TestCleanContainedSymlinkTarget(t *testing.T) {
	// relative targets are anchored at the link's directory
	got, err := cleanContainedSymlinkTarget("/dir/link", "file.txt")
	require.NoError(t, err)
	assert.Equal(t, "/dir/file.txt", got)

	got, err = cleanContainedSymlinkTarget("/dir/link", "../file.txt")
	require.NoError(t, err)
	assert.Equal(t, "/file.txt", got)

	got, err = cleanContainedSymlinkTarget("/dir/link", "/abs/file.txt")
	require.NoError(t, err)
	assert.Equal(t, "/abs/file.txt", got)

	// targets that resolve outside the root are refused. From a link at the
	// root, even a single parent traversal escapes; deeper links need two.
	for _, tc := range []struct {
		linkpath, target string
	}{
		{"/link", "../escape"},
		{"/dir/link", "../../etc/passwd"},
		{"/dir/link", "/../escape"},
		{"/dir/sub/link", "../../../etc/passwd"},
	} {
		_, err := cleanContainedSymlinkTarget(tc.linkpath, tc.target)
		require.Error(t, err, tc.target)
		assert.True(t, errors.Is(err, os.ErrPermission), "expected permission error for %q, got %v", tc.target, err)
	}
}

func TestCheckRootWritable(t *testing.T) {
	require.NoError(t, checkRootWritable("/a", "Mkdir"))
	err := checkRootWritable("/", "Mkdir")
	require.Error(t, err)
	assert.True(t, errors.Is(err, os.ErrPermission))

	// read-only methods may still target the root
	for _, method := range []string{"Get", "Stat", "Lstat", "List", "Readlink", "StatVFS"} {
		require.NoError(t, checkRootWritable("/", method), method)
	}
}

// assertPermissionDenied checks that the client saw SSH_FX_PERMISSION_DENIED.
// normaliseError turns that status into os.ErrPermission.
func assertPermissionDenied(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	assert.True(t, errors.Is(err, os.ErrPermission),
		"expected os.ErrPermission (SSH_FX_PERMISSION_DENIED), got %v", err)
}

// A client must never be able to name a path outside the virtual root, even
// using lexical traversal. Every request path is normalized and re-checked
// before any handler runs.
func TestRequestRejectsTraversal(t *testing.T) {
	p := clientRequestServerPair(t)
	defer p.Close()

	_, err := putTestFile(p.cli, "/../escape", "x")
	assertPermissionDenied(t, err)

	_, err = p.cli.OpenFile("/a/../../etc/passwd", os.O_RDONLY)
	assertPermissionDenied(t, err)

	err = p.cli.Mkdir("/../escape-dir")
	assertPermissionDenied(t, err)

	err = p.cli.Rename("/../escape", "/x")
	assertPermissionDenied(t, err)

	err = p.cli.PosixRename("/x", "/../escape")
	assertPermissionDenied(t, err)

	err = p.cli.Remove("/../escape")
	assertPermissionDenied(t, err)

	err = p.cli.RemoveDirectory("/../escape-dir")
	assertPermissionDenied(t, err)

	err = p.cli.Symlink("ok", "/../link")
	assertPermissionDenied(t, err)

	_, err = p.cli.Stat("/../../etc/passwd")
	assertPermissionDenied(t, err)

	// nothing escaped into the in-memory file system
	handler := p.testHandler()
	handler.mu.Lock()
	defer handler.mu.Unlock()
	for name := range handler.files {
		assert.NotEqual(t, "/escape", name)
		assert.NotEqual(t, "/etc/passwd", name)
		assert.NotEqual(t, "/escape-dir", name)
	}
}

// Traversal also applies to the second path of rename/symlink style requests.
func TestRequestRejectsTraversalInTarget(t *testing.T) {
	p := clientRequestServerPair(t)
	defer p.Close()

	_, err := putTestFile(p.cli, "/foo", "hello")
	require.NoError(t, err)

	err = p.cli.Rename("/foo", "/../escape")
	assertPermissionDenied(t, err)

	// a symlink whose linkpath is inside the root but whose target escapes
	err = p.cli.Symlink("../escape", "/link")
	assertPermissionDenied(t, err)

	// the original file must be untouched
	content, err := getTestFile(p.cli, "/foo")
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), content)
}

// Mutating requests against the root itself are refused; read requests work.
func TestRequestRootIsNotWritable(t *testing.T) {
	p := clientRequestServerPair(t)
	defer p.Close()

	// root reads are fine
	_, err := p.cli.ReadDir("/")
	require.NoError(t, err)
	_, err = p.cli.Stat("/")
	require.NoError(t, err)

	// root writes are refused before reaching the handlers
	_, err = p.cli.Create("/")
	assertPermissionDenied(t, err)

	_, err = p.cli.OpenFile("/", os.O_WRONLY|os.O_CREATE)
	assertPermissionDenied(t, err)

	// a read-only open of the root must not be blocked by the write gate
	// (the backend may still reject opening a directory itself)
	_, err = p.cli.OpenFile("/", os.O_RDONLY)
	assert.True(t, err == nil || !errors.Is(err, os.ErrPermission),
		"read-only root open must not return permission denied, got %v", err)

	err = p.cli.Mkdir("/")
	assertPermissionDenied(t, err)

	err = p.cli.RemoveDirectory("/")
	assertPermissionDenied(t, err)

	err = p.cli.Chmod("/", 0o700)
	assertPermissionDenied(t, err)

	_, err = putTestFile(p.cli, "/foo", "hello")
	require.NoError(t, err)
	err = p.cli.Rename("/foo", "/")
	assertPermissionDenied(t, err)
	err = p.cli.PosixRename("/foo", "/")
	assertPermissionDenied(t, err)

	assert.Len(t, p.svr.openRequests, 0, "refused requests must not leave handles behind")
}

// A refused request is an SFTP status reply for that request only: the same
// session must keep serving subsequent, legitimate requests.
func TestRequestRejectionIsPerRequest(t *testing.T) {
	p := clientRequestServerPair(t)
	defer p.Close()

	for range 5 {
		_, err := putTestFile(p.cli, "/../escape", "x")
		assertPermissionDenied(t, err)

		_, err = putTestFile(p.cli, "/ok", "still here")
		require.NoError(t, err)
	}

	content, err := getTestFile(p.cli, "/ok")
	require.NoError(t, err)
	assert.Equal(t, []byte("still here"), content)

	entries, err := p.cli.ReadDir("/")
	require.NoError(t, err)
	assert.Len(t, entries, 1)

	assert.Len(t, p.svr.openRequests, 0)
}

// escapeResolver wraps the in-memory handler and simulates a backend whose
// symbolic links resolve to storage outside the gateway root.
type escapeResolver struct {
	*root
	// escaped maps an in-root path to the (out-of-root) location it resolves to.
	escaped map[string]string
}

func (h *escapeResolver) ResolvePath(p string) (string, error) {
	if target, ok := h.escaped[p]; ok {
		return target, nil
	}
	return h.root.ResolvePath(p)
}

func newEscapeHandler(escaped map[string]string) Handlers {
	h := &escapeResolver{
		root:    InMemHandler().FileGet.(*root),
		escaped: escaped,
	}
	return Handlers{h, h, h, h}
}

// A symbolic link whose resolution lands outside the root is rejected with a
// permission error, for every request type that follows symbolic links.
func TestRequestRejectsResolvedSymlinkEscape(t *testing.T) {
	escaped := map[string]string{
		"/evil":         "/../outside/evil",
		"/evildir":      "/../outside/evildir",
		"/renametarget": "/../outside/renamed",
	}
	p := clientRequestServerPairWithHandlers(t, newEscapeHandler(escaped))
	defer p.Close()

	// follow-link reads and stats
	_, err := p.cli.Stat("/evil")
	assertPermissionDenied(t, err)

	_, err = p.cli.OpenFile("/evil", os.O_RDONLY)
	assertPermissionDenied(t, err)

	_, err = p.cli.OpenFile("/evil", os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	assertPermissionDenied(t, err)

	_, err = p.cli.ReadDir("/evildir")
	assertPermissionDenied(t, err)

	// setstat follows links too
	err = p.cli.Chmod("/evil", 0o600)
	assertPermissionDenied(t, err)

	// rename where either endpoint resolves outside
	_, err = putTestFile(p.cli, "/foo", "hello")
	require.NoError(t, err)
	err = p.cli.Rename("/foo", "/renametarget")
	assertPermissionDenied(t, err)
	err = p.cli.PosixRename("/foo", "/renametarget")
	assertPermissionDenied(t, err)
	err = p.cli.Rename("/evil", "/inside")
	assertPermissionDenied(t, err)

	// Lstat and Readlink do not follow links and remain available so clients
	// can inspect the link itself.
	err = p.cli.Symlink("/foo", "/link-inside")
	require.NoError(t, err)
	target, err := p.cli.ReadLink("/link-inside")
	require.NoError(t, err)
	assert.Equal(t, "/foo", target)
	_, err = p.cli.Lstat("/link-inside")
	require.NoError(t, err)

	assert.Len(t, p.svr.openRequests, 0)

	// legitimate traffic in the same session still works
	content, err := getTestFile(p.cli, "/foo")
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), content)
}

// RealPath results, including those from a custom RealPathFileLister, must
// not be allowed to advertise a location outside the root.
func TestRequestRealpathStaysContained(t *testing.T) {
	// built-in lexical implementation clamps traversal to the root
	p := clientRequestServerPair(t)
	defer p.Close()

	realPath, err := p.cli.RealPath("../..")
	require.NoError(t, err)
	assert.Equal(t, "/", realPath)

	// a custom RealPath implementation returning an out-of-root location is
	// rejected by the server side containment check
	escaping := &escapingRealPather{
		root: root{
			rootFile: &memFile{name: "/", modtime: time.Now(), isdir: true},
			files:    make(map[string]*memFile),
		},
	}
	handlers := Handlers{escaping, escaping, escaping, escaping}
	p2 := clientRequestServerPairWithHandlers(t, handlers)
	defer p2.Close()

	_, err = p2.cli.RealPath("/anything")
	assertPermissionDenied(t, err)

	// the root itself still resolves inside the root
	realPath, err = p2.cli.RealPath("/")
	require.NoError(t, err)
	assert.Equal(t, "/", realPath)
}

// escapingRealPather is an in-memory file system whose RealPath
// implementation always advertises a location outside the root, except for
// the root itself.
type escapingRealPather struct {
	root
}

func (fs *escapingRealPather) RealPath(p string) (string, error) {
	if fs.mockErr != nil {
		return "", fs.mockErr
	}
	cleaned := cleanPath(p)
	if cleaned == "/" {
		return "/", nil
	}
	return "/../outside" + cleaned, nil
}
