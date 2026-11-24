package sftp

import (
	"context"
	"errors"
	"io"
	"path"
	"path/filepath"
	"strconv"
	"sync"
)

const defaultMaxTxPacket uint32 = 1 << 15

// Handlers contains the 4 SFTP server request handlers.
type Handlers struct {
	FileGet  FileReader
	FilePut  FileWriter
	FileCmd  FileCmder
	FileList FileLister
}

// RequestServer abstracts the sftp protocol with an http request-like protocol
type RequestServer struct {
	Handlers Handlers

	*serverConn
	pktMgr *packetManager

	startDirectory string
	maxTxPacket    uint32

	mu           sync.RWMutex
	handleCount  int
	openRequests map[string]*Request
}

// A RequestServerOption is a function which applies configuration to a RequestServer.
type RequestServerOption func(*RequestServer)

// WithRSAllocator enable the allocator.
// After processing a packet we keep in memory the allocated slices
// and we reuse them for new packets.
// The allocator is experimental
func WithRSAllocator() RequestServerOption {
	return func(rs *RequestServer) {
		alloc := newAllocator()
		rs.pktMgr.alloc = alloc
		rs.conn.alloc = alloc
	}
}

// WithStartDirectory sets a start directory to use as base for relative paths.
// If unset the default is "/"
func WithStartDirectory(startDirectory string) RequestServerOption {
	return func(rs *RequestServer) {
		rs.startDirectory = cleanPath(startDirectory)
	}
}

// WithRSMaxTxPacket sets the maximum size of the payload returned to the client,
// measured in bytes. The default value is 32768 bytes, and this option
// can only be used to increase it. Setting this option to a larger value
// should be safe, because the client decides the size of the requested payload.
//
// The default maximum packet size is 32768 bytes.
func WithRSMaxTxPacket(size uint32) RequestServerOption {
	return func(rs *RequestServer) {
		if size < defaultMaxTxPacket {
			return
		}

		rs.maxTxPacket = size
	}
}

// NewRequestServer creates/allocates/returns new RequestServer.
// Normally there will be one server per user-session.
func NewRequestServer(rwc io.ReadWriteCloser, h Handlers, options ...RequestServerOption) *RequestServer {
	svrConn := &serverConn{
		conn: conn{
			Reader:      rwc,
			WriteCloser: rwc,
		},
	}
	rs := &RequestServer{
		Handlers: h,

		serverConn: svrConn,
		pktMgr:     newPktMgr(svrConn),

		startDirectory: "/",
		maxTxPacket:    defaultMaxTxPacket,

		openRequests: make(map[string]*Request),
	}

	for _, o := range options {
		o(rs)
	}
	return rs
}

// New Open packet/Request
func (rs *RequestServer) nextRequest(r *Request) string {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	rs.handleCount++

	r.handle = strconv.Itoa(rs.handleCount)
	rs.openRequests[r.handle] = r

	return r.handle
}

// Returns Request from openRequests, bool is false if it is missing.
//
// The Requests in openRequests work essentially as open file descriptors that
// you can do different things with. What you are doing with it are denoted by
// the first packet of that type (read/write/etc).
func (rs *RequestServer) getRequest(handle string) (*Request, bool) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	r, ok := rs.openRequests[handle]
	return r, ok
}

// Close the Request and clear from openRequests map
func (rs *RequestServer) closeRequest(handle string) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if r, ok := rs.openRequests[handle]; ok {
		delete(rs.openRequests, handle)
		return r.close()
	}

	return EBADF
}

// Close the read/write/closer to trigger exiting the main server loop
func (rs *RequestServer) Close() error { return rs.conn.Close() }

func (rs *RequestServer) serveLoop(pktChan chan<- orderedRequest) error {
	defer close(pktChan) // shuts down sftpServerWorkers

	var err error
	var pkt requestPacket
	var pktType fxp
	var pktBytes []byte

	for {
		pktType, pktBytes, err = rs.serverConn.recvPacket(rs.pktMgr.getNextOrderID())
		if err != nil {
			// we don't care about releasing allocated pages here, the server will quit and the allocator freed
			return err
		}

		pkt, err = makePacket(rxPacket{pktType, pktBytes})
		if err != nil {
			switch {
			case errors.Is(err, errUnknownExtendedPacket):
				// do nothing
			default:
				debug("makePacket err: %v", err)
				rs.conn.Close() // shuts down recvPacket
				return err
			}
		}

		pktChan <- rs.pktMgr.newOrderedRequest(pkt)
	}
}

// Serve requests for user session
func (rs *RequestServer) Serve() error {
	defer func() {
		if rs.pktMgr.alloc != nil {
			rs.pktMgr.alloc.Free()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	runWorker := func(ch chan orderedRequest) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := rs.packetWorker(ctx, ch); err != nil {
				rs.conn.Close() // shuts down recvPacket
			}
		}()
	}
	pktChan := rs.pktMgr.workerChan(runWorker)

	err := rs.serveLoop(pktChan)

	wg.Wait() // wait for all workers to exit

	rs.mu.Lock()
	defer rs.mu.Unlock()

	// make sure all open requests are properly closed
	// (eg. possible on dropped connections, client crashes, etc.)
	for handle, req := range rs.openRequests {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		req.transferError(err)

		delete(rs.openRequests, handle)
		req.close()
	}

	return err
}

func (rs *RequestServer) packetWorker(ctx context.Context, pktChan chan orderedRequest) error {
	for pkt := range pktChan {
		orderID := pkt.orderID()
		if epkt, ok := pkt.requestPacket.(*sshFxpExtendedPacket); ok {
			if epkt.SpecificPacket != nil {
				pkt.requestPacket = epkt.SpecificPacket
			}
		}

		var rpkt responsePacket
		switch pkt := pkt.requestPacket.(type) {
		case *sshFxInitPacket:
			rpkt = &sshFxVersionPacket{Version: sftpProtocolVersion, Extensions: sftpExtensions}
		case *sshFxpClosePacket:
			handle := pkt.getHandle()
			rpkt = statusFromError(pkt.ID, rs.closeRequest(handle))
		case *sshFxpRealpathPacket:
			rpkt = rs.realpathPacket(pkt)
		case *sshFxpOpendirPacket:
			request, err := requestFromPacket(ctx, pkt, rs.startDirectory)
			if err == nil {
				err = rs.resolveRequest(request)
			}
			if err != nil {
				rpkt = statusFromError(pkt.ID, err)
				if request != nil {
					request.close()
				}
			} else {
				rpkt = request.opendir(rs.Handlers, pkt)
				if hpkt, ok := rpkt.(*sshFxpHandlePacket); ok {
					// Only publish the handle once the Request is fully set up:
					// a pipelined READ/WRITE on it is handled concurrently.
					hpkt.Handle = rs.nextRequest(request)
				} else {
					request.close()
				}
			}
		case *sshFxpOpenPacket:
			request, err := requestFromPacket(ctx, pkt, rs.startDirectory)
			if err == nil {
				// A read-only open of the root is allowed; only writes are
				// refused. The same flags select the Put/Open methods in
				// request.open().
				pflags := request.Pflags()
				if pflags.Write || pflags.Append || pflags.Creat || pflags.Trunc {
					err = checkRootWritable(request.Filepath, "Open")
				}
			}
			if err == nil {
				err = rs.resolveRequest(request)
			}
			if err != nil {
				rpkt = statusFromError(pkt.ID, err)
				if request != nil {
					request.close()
				}
			} else {
				rpkt = request.open(rs.Handlers, pkt)
				if hpkt, ok := rpkt.(*sshFxpHandlePacket); ok {
					// Only publish the handle once the Request is fully set up:
					// a pipelined READ/WRITE on it is handled concurrently.
					hpkt.Handle = rs.nextRequest(request)
				} else {
					request.close()
				}
			}
		case *sshFxpFstatPacket:
			handle := pkt.getHandle()
			request, ok := rs.getRequest(handle)
			if !ok {
				rpkt = statusFromError(pkt.ID, EBADF)
			} else {
				filepath, err := cleanContainedPath(rs.startDirectory, request.Filepath)
				if err != nil {
					rpkt = statusFromError(pkt.ID, err)
				} else {
					request = &Request{
						Method:   "Stat",
						Filepath: filepath,
					}
					rpkt = request.call(rs.Handlers, pkt, rs.pktMgr.alloc, orderID, rs.maxTxPacket)
				}
			}
		case *sshFxpFsetstatPacket:
			handle := pkt.getHandle()
			request, ok := rs.getRequest(handle)
			if !ok {
				rpkt = statusFromError(pkt.ID, EBADF)
			} else {
				filepath, err := cleanContainedPath(rs.startDirectory, request.Filepath)
				if err != nil {
					rpkt = statusFromError(pkt.ID, err)
				} else if err = checkRootWritable(filepath, "Setstat"); err != nil {
					rpkt = statusFromError(pkt.ID, err)
				} else {
					request = &Request{
						Method:   "Setstat",
						Filepath: filepath,
					}
					rpkt = request.call(rs.Handlers, pkt, rs.pktMgr.alloc, orderID, rs.maxTxPacket)
				}
			}
		case *sshFxpExtendedPacketPosixRename:
			filepath, err := cleanContainedPath(rs.startDirectory, pkt.Oldpath)
			if err == nil {
				var target string
				target, err = cleanContainedPath(rs.startDirectory, pkt.Newpath)
				if err == nil {
					request := &Request{
						Method:   "PosixRename",
						Filepath: filepath,
						Target:   target,
					}
					err = checkRootWritable(filepath, "PosixRename")
					if err == nil {
						err = checkRootWritable(target, "PosixRename")
					}
					if err == nil {
						err = rs.resolveRequest(request)
					}
					if err == nil {
						rpkt = request.call(rs.Handlers, pkt, rs.pktMgr.alloc, orderID, rs.maxTxPacket)
					}
				}
			}
			if err != nil {
				rpkt = statusFromError(pkt.id(), err)
			}
		case *sshFxpExtendedPacketStatVFS:
			filepath, err := cleanContainedPath(rs.startDirectory, pkt.Path)
			if err != nil {
				rpkt = statusFromError(pkt.ID, err)
			} else {
				request := &Request{
					Method:   "StatVFS",
					Filepath: filepath,
				}
				rpkt = request.call(rs.Handlers, pkt, rs.pktMgr.alloc, orderID, rs.maxTxPacket)
			}
		case hasHandle:
			handle := pkt.getHandle()
			request, ok := rs.getRequest(handle)
			if !ok {
				rpkt = statusFromError(pkt.id(), EBADF)
			} else {
				rpkt = request.call(rs.Handlers, pkt, rs.pktMgr.alloc, orderID, rs.maxTxPacket)
			}
		case hasPath:
			request, err := requestFromPacket(ctx, pkt, rs.startDirectory)
			if err != nil {
				rpkt = statusFromError(pkt.id(), err)
			} else {
				err = checkRootWritable(request.Filepath, request.Method)
				if err == nil && request.Target != "" {
					err = checkRootWritable(request.Target, request.Method)
				}
				if err == nil {
					err = rs.resolveRequest(request)
				}
				if err != nil {
					rpkt = statusFromError(pkt.id(), err)
				} else {
					rpkt = request.call(rs.Handlers, pkt, rs.pktMgr.alloc, orderID, rs.maxTxPacket)
				}
				request.close()
			}
		default:
			rpkt = statusFromError(pkt.id(), ErrSSHFxOpUnsupported)
		}

		rs.pktMgr.readyPacket(
			rs.pktMgr.newOrderedResponse(rpkt, orderID))
	}
	return nil
}

// realpathPacket handles SSH_FXP_REALPATH. The built-in lexical
// implementation preserves its historical clamping semantics (a traversal
// like "../.." is folded onto the root rather than rejected), while a custom
// RealPathFileLister result is still containment-checked so backends cannot
// advertise a location outside the root.
func (rs *RequestServer) realpathPacket(pkt *sshFxpRealpathPacket) responsePacket {
	var realPath string
	var err error
	custom := false

	switch pather := rs.Handlers.FileList.(type) {
	case RealPathFileLister:
		realPath, err = pather.RealPath(pkt.getPath())
		custom = true
	case legacyRealPathFileLister:
		realPath = pather.RealPath(pkt.getPath())
		custom = true
	default:
		realPath = cleanPathWithBase(rs.startDirectory, pkt.getPath())
	}
	if err == nil && custom {
		// Check containment before cleaning so traversal segments cannot be
		// erased into an apparently in-root path.
		err = checkContained(filepath.ToSlash(realPath))
	}
	if err == nil {
		// Normalize into a canonical absolute POSIX spelling for the reply.
		realPath = cleanPath(realPath)
	}
	if err != nil {
		return statusFromError(pkt.ID, err)
	}
	return cleanPacketPath(pkt, realPath)
}

// resolveRequest applies backend provided symbolic link resolution to a
// request and verifies that the resolved location is still inside the root.
// It is a no-op when the backend does not implement PathResolver, and for
// methods that must not follow symbolic links (Lstat, Readlink) or only
// create them (Symlink, where the target is validated in requestFromPacket).
func (rs *RequestServer) resolveRequest(r *Request) error {
	if r.Method == "Lstat" || r.Method == "Readlink" || r.Method == "Symlink" {
		return nil
	}

	resolver, ok := rs.Handlers.FileList.(PathResolver)
	if !ok {
		return nil
	}

	resolved, err := resolver.ResolvePath(r.Filepath)
	if err != nil {
		return err
	}
	// Check containment before cleaning: the resolved path may contain
	// traversal segments produced by following symbolic links, and cleaning
	// them first would hide an escape. Once it is proven safe, normalize it
	// into the canonical spelling backends expect.
	resolved = filepath.ToSlash(resolved)
	if err = checkContained(resolved); err != nil {
		return err
	}
	r.Filepath = path.Clean(resolved)

	if r.Target != "" {
		var target string
		target, err = resolver.ResolvePath(r.Target)
		if err != nil {
			return err
		}
		target = filepath.ToSlash(target)
		if err = checkContained(target); err != nil {
			return err
		}
		r.Target = path.Clean(target)
	}

	return nil
}

// clean and return name packet for file
func cleanPacketPath(pkt *sshFxpRealpathPacket, realPath string) responsePacket {
	return &sshFxpNamePacket{
		ID: pkt.id(),
		NameAttrs: []*sshFxpNameAttr{
			{
				Name:     realPath,
				LongName: realPath,
				Attrs:    emptyFileStat,
			},
		},
	}
}

// Makes sure we have a clean POSIX (/) absolute path to work with
func cleanPath(p string) string {
	return cleanPathWithBase("/", p)
}

func cleanPathWithBase(base, p string) string {
	p = filepath.ToSlash(filepath.Clean(p))
	if !path.IsAbs(p) {
		return path.Join(base, p)
	}
	return p
}
