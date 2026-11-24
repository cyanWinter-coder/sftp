# Request Based SFTP API

The request based API allows for custom backends in a way similar to the http
package. In order to create a backend you need to implement 4 handler
interfaces; one for reading, one for writing, one for misc commands and one for
listing files. Each has 1 required method and in each case those methods take
the Request as the only parameter and they each return something different.
These 4 interfaces are enough to handle all the SFTP traffic in a simplified
manner.

The Request structure has 5 public fields which you will deal with.

- Method (string) - string name of incoming call
- Filepath (string) - POSIX path of file to act on
- Flags (uint32) - 32bit bitmask value of file open/create flags
- Attrs ([]byte) - byte string of file attribute data
- Target (string) - target path for renames and sym-links

Below are the methods and a brief description of what they need to do.

### Fileread(*Request) (io.Reader, error)

Handler for "Get" method and returns an io.Reader for the file which the server
then sends to the client.

### Filewrite(*Request) (io.Writer, error)

Handler for "Put" method and returns an io.Writer for the file which the server
then writes the uploaded file to. The file opening "pflags" are currently
preserved in the Request.Flags field as a 32bit bitmask value. See the [SFTP
spec](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.3) for
details.

###    Filecmd(*Request) error

Handles "SetStat", "Rename", "Rmdir", "Mkdir"  and "Symlink" methods. Makes the
appropriate changes and returns nil for success or an filesystem like error
(eg. os.ErrNotExist). The attributes are currently propagated in their raw form
([]byte) and will need to be unmarshalled to be useful. See the respond method
on sshFxpSetstatPacket for example of you might want to do this.

### Fileinfo(*Request) ([]os.FileInfo, error)

Handles "List", "Stat", "Readlink" methods. Gathers/creates FileInfo structs
with the data on the files and returns in a list (list of 1 for Stat and
Readlink).

## Path containment

The RequestServer treats every request independently and enforces that no
request can reach storage outside the virtual root.

- Every request path is normalized and re-checked against the root before any
  handler runs. A lexical traversal such as `../../etc/passwd` is rejected with
  `SSH_FX_PERMISSION_DENIED`; cleaning the path first would erase the `..`
  segments, so the check runs on the un-cleaned path.
- A request whose normalized location targets the root itself is allowed for
  read operations but refused for mutating operations, so nothing can write
  through the root. An empty or `.` path resolves to the start directory, not
  to anything above it.
- A rejected request only produces an error status packet for that request;
  other requests on the same session are unaffected.

Because the server only sees virtual POSIX paths, it cannot resolve symbolic
links by itself. A backend backed by a real or shared file system should
implement the optional `PathResolver` interface:

```go
type PathResolver interface {
	ResolvePath(p string) (string, error)
}
```

For each request that follows symbolic links (every method except `Lstat`,
`Readlink` and `Symlink`) the server calls `ResolvePath` on the cleaned,
already verified in-root path, then re-checks that the returned real location
is still inside the root. A resolved path that escapes is rejected with
`SSH_FX_PERMISSION_DENIED` before the handler runs. The target of a
`Symlink` request is validated at creation time instead.



## TODO

- Add support for API users to see trace/debugging info of what is going on
inside SFTP server.
- Unmarshal the file attributes into a structure on the Request object.
