package sftp

import (
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// PathResolver is an optional handler interface for backends that can resolve
// the real, on-storage location of a virtual path, following any symbolic
// links it encounters.
//
// The RequestServer only sees POSIX style virtual paths and has no knowledge
// of the backend storage, so it cannot resolve symbolic links on its own.
// A backend that serves paths from a shared or real file system should
// implement this interface: the server then calls ResolvePath for every
// request that follows symbolic links and re-checks that the resolved path
// stays inside the configured root. A resolved path escaping the root is
// rejected with SSH_FX_PERMISSION_DENIED before any handler runs.
//
// ResolvePath receives a request path that has already been cleaned and
// lexically verified to be inside the root. It must return the cleaned,
// absolute, in-root path that the request ultimately reaches after following
// symbolic links. If the path (or an intermediate component) does not exist,
// it should return an error satisfying os.IsNotExist; the server maps that to
// SSH_FX_NO_SUCH_FILE instead of touching any storage outside the root.
//
// It is called from request handling goroutines and must be safe for
// concurrent use.
type PathResolver interface {
	ResolvePath(p string) (string, error)
}

// rootDeniedError reports that a request path resolved outside the gateway
// root. It embeds the SSH_FX_PERMISSION_DENIED status directly, so
// statusFromError maps it to that SFTP code on every platform without
// depending on a platform specific syscall errno. It is wrapped in an
// *os.PathError for a familiar "open <path>: ..." message.
type rootDeniedError struct {
	fxerr
	path string
}

func newRootDeniedError(p string) error {
	return &os.PathError{
		Op:   "open",
		Path: p,
		Err: &rootDeniedError{
			fxerr: fxerr(sshFxPermissionDenied),
			path:  p,
		},
	}
}

func (e *rootDeniedError) Error() string {
	return "sftp: path is outside of the root: " + e.path
}

// Unwrap exposes the embedded SSH_FX_PERMISSION_DENIED status so errors.As
// can match the fxerr when statusFromError translates the error.
func (e *rootDeniedError) Unwrap() error {
	return e.fxerr
}

// Is makes the whole error chain satisfy errors.Is(err, os.ErrPermission),
// in addition to the SFTP status code exposed via Unwrap.
func (e *rootDeniedError) Is(target error) bool {
	return target == os.ErrPermission || errors.Is(e.fxerr, target)
}

// checkContained verifies that an absolute, slash separated POSIX path is the
// virtual root or located beneath it, without erasing ".." components first.
// A backend PathResolver may legitimately return an un-cleaned path whose
// traversal segments lead outside the root (for example
// "/tenant/../../etc/passwd"); cleaning that before the check would hide the
// escape. A ".." at depth zero is precisely the condition of climbing past
// the root, so the per-segment depth check is both necessary and sufficient.
func checkContained(p string) error {
	depth := 0
	for _, segment := range strings.Split(p, "/") {
		switch segment {
		case "", ".":
			continue
		case "..":
			if depth == 0 {
				return newRootDeniedError(p)
			}
			depth--
		default:
			depth++
		}
	}
	return nil
}

// cleanContainedPath cleans p relative to base (the configured start
// directory) and verifies that the result stays inside the virtual root "/".
// Absolute input paths are interpreted against the virtual root rather than
// the start directory, matching the behaviour of cleanPathWithBase.
//
// Containment is checked before lexical cleaning: a traversal such as
// "/a/../../etc/passwd" must be rejected even though cleaning it would erase
// the ".." segments and hide the escape.
//
// It returns the cleaned absolute POSIX path, or an *os.PathError wrapping a
// permission error if the lexical resolution escapes the root.
func cleanContainedPath(base, p string) (string, error) {
	// Reconstruct the un-cleaned joined path for the containment check so a
	// raw ".." traversal is still visible. A relative p is anchored at base;
	// an absolute p is taken as-is (the virtual root is "/"). String
	// concatenation is deliberate: path.Join/filepath.Clean would erase the
	// traversal segments before the check.
	raw := filepath.ToSlash(p)
	joined := raw
	if !path.IsAbs(raw) {
		joined = strings.TrimSuffix(base, "/") + "/" + raw
	}
	if err := checkContained(joined); err != nil {
		return "", err
	}

	return cleanPathWithBase(base, p), nil
}

// cleanContainedSymlinkTarget normalizes the raw target string of a
// SSH_FXP_SYMLINK request. A relative target is interpreted relative to the
// directory that contains the link (linkpath must already be a cleaned,
// absolute in-root path). Containment is checked against the un-cleaned
// joined path, so a target whose traversal climbs past the virtual root is
// rejected before the symbolic link is created: such a link could otherwise
// be followed by later requests and write through into another tenant's
// storage.
func cleanContainedSymlinkTarget(linkpath, target string) (string, error) {
	// String concatenation keeps traversal segments visible for the check;
	// path.Join/filepath.Clean would erase them first.
	raw := filepath.ToSlash(target)
	joined := raw
	if !path.IsAbs(raw) {
		joined = strings.TrimSuffix(path.Dir(linkpath), "/") + "/" + raw
	}
	if err := checkContained(joined); err != nil {
		return "", err
	}

	return path.Clean(joined), nil
}

// rootWritingMethods are request methods that create, remove or modify a file
// system entry at the given path. Opening the root itself for one of them is a
// write through the gateway boundary and is refused; read-only methods may
// still target the root.
var rootWritingMethods = map[string]bool{
	"Put":         true,
	"Open":        true, // Open only reaches the handlers for write flags
	"Setstat":     true,
	"Rename":      true,
	"PosixRename": true,
	"Remove":      true,
	"Rmdir":       true,
	"Mkdir":       true,
	"Link":        true,
	"Symlink":     true,
}

// checkRootWritable enforces that mutating operations can never target the
// virtual root directory itself. Read requests (Get, Stat, Lstat, List,
// Readlink, StatVFS) against the root are still allowed.
func checkRootWritable(p string, method string) error {
	if rootWritingMethods[method] && p == "/" {
		return newRootDeniedError(p)
	}
	return nil
}
