// An example SFTP server implementation using the golang SSH package.
// Serves the whole filesystem visible to the user, and has a hard-coded username and password,
// so not for real use!
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Based on example server code from golang.org/x/crypto/ssh and server_standalone
func main() {
	var (
		readOnly         bool
		debugStderr      bool
		winRoot          bool
		maxConnections   int
		idleTimeout      time.Duration
		handshakeTimeout time.Duration
		addr             string
	)

	flag.BoolVar(&readOnly, "R", false, "read-only server")
	flag.BoolVar(&debugStderr, "e", false, "debug to stderr")
	flag.BoolVar(&winRoot, "wr", false, "windows root")
	flag.IntVar(&maxConnections, "max-conns", 200, "maximum concurrent SSH connections")
	flag.DurationVar(&idleTimeout, "idle-timeout", 5*time.Minute, "disconnect idle SFTP connections (0 to disable)")
	flag.DurationVar(&handshakeTimeout, "handshake-timeout", 30*time.Second, "maximum SSH/SFTP handshake duration (0 to disable)")
	flag.StringVar(&addr, "addr", "0.0.0.0:2022", "listen address")

	flag.Parse()

	debugStream := io.Discard
	if debugStderr {
		debugStream = os.Stderr
	}

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Should use constant-time compare (or better, salt+hash) in
			// a production setting. c.User() belongs to this handshake and
			// must not be copied into shared/mutable state.
			fmt.Fprintf(debugStream, "Login: %s\n", c.User())
			if c.User() == "testuser" && string(pass) == "tiger" {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}

	privateBytes, err := os.ReadFile("id_rsa")
	if err != nil {
		log.Fatal("Failed to load private key", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key", err)
	}

	config.AddHostKey(private)

	limiter, err := sftp.NewConnectionLimiter(maxConnections)
	if err != nil {
		log.Fatal(err)
	}

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal("failed to listen for connection", err)
	}
	fmt.Printf("Listening on %v (max connections: %d)\n", listener.Addr(), maxConnections)

	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept incoming connection: %v", err)
			continue
		}

		// Reject before starting an expensive SSH handshake when the limit is
		// full. Acquire is non-blocking and does not affect live connections.
		release, err := limiter.Acquire()
		if err != nil {
			log.Printf("rejecting %s: %v", nConn.RemoteAddr(), err)
			_ = nConn.Close()
			continue
		}

		go handleConnection(nConn, config, release, debugStream, readOnly, winRoot, idleTimeout, handshakeTimeout)
	}
}

func handleConnection(
	nConn net.Conn,
	config *ssh.ServerConfig,
	release func(),
	debugStream io.Writer,
	readOnly bool,
	winRoot bool,
	idleTimeout time.Duration,
	handshakeTimeout time.Duration,
) {
	defer release()
	defer nConn.Close()

	if handshakeTimeout > 0 {
		_ = nConn.SetDeadline(time.Now().Add(handshakeTimeout))
	}

	// Before use, a handshake must be performed on the incoming net.Conn.
	// On authentication failure x/crypto/ssh closes the network connection;
	// the deferred close/release below is still responsible for this slot.
	sshConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Printf("failed to handshake for %s: %v", nConn.RemoteAddr(), err)
		return
	}
	defer sshConn.Close()

	// Keep the handshake deadline until the client opens its session channel.
	// The SFTP Server installs idle detection for the established channel.
	username := sshConn.User()
	fmt.Fprintf(debugStream, "SSH server established for %q\n", username)

	// The incoming Request channel must be serviced.
	go ssh.DiscardRequests(reqs)

	// Service incoming channels. Each channel gets its own SFTP Server and
	// therefore its own handshake/auth state and handle table.
	for newChannel := range chans {
		_ = nConn.SetDeadline(time.Time{})

		// The SFTP subsystem owns the rest of this SSH connection. Serving it
		// synchronously ensures that an idle close releases the concurrency slot.
		if handleChannel(newChannel, username, sshConn, debugStream, readOnly, winRoot, idleTimeout, handshakeTimeout) {
			return
		}
	}
}

// handleChannel returns true when the SFTP session has terminated and the SSH
// connection should be closed.
func handleChannel(
	newChannel ssh.NewChannel,
	username string,
	sshMetadata ssh.ConnMetadata,
	debugStream io.Writer,
	readOnly bool,
	winRoot bool,
	idleTimeout time.Duration,
	handshakeTimeout time.Duration,
) bool {
	fmt.Fprintf(debugStream, "Incoming channel for %q: %s\n", username, newChannel.ChannelType())
	if newChannel.ChannelType() != "session" {
		_ = newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		fmt.Fprintf(debugStream, "Unknown channel type: %s\n", newChannel.ChannelType())
		return false
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("could not accept channel for %q: %v", username, err)
		return false
	}
	defer channel.Close()

	fmt.Fprintf(debugStream, "Channel accepted for %q\n", username)

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env".
	// Here we handle only the "subsystem" request.
	go func(in <-chan *ssh.Request) {
		for req := range in {
			fmt.Fprintf(debugStream, "Request for %q: %v\n", username, req.Type)
			ok := false
			switch req.Type {
			case "subsystem":
				if len(req.Payload) >= 4 {
					fmt.Fprintf(debugStream, "Subsystem: %s\n", req.Payload[4:])
					if string(req.Payload[4:]) == "sftp" {
						ok = true
					}
				}
			}
			fmt.Fprintf(debugStream, " - accepted: %v\n", ok)
			_ = req.Reply(ok, nil)
		}
	}(requests)

	serverOptions := []sftp.ServerOption{
		sftp.WithDebug(debugStream),
		// Bind the already-authenticated SSH identity to this Server only.
		sftp.WithSSHConnection(sshMetadata),
		sftp.WithIdleTimeout(idleTimeout),
		sftp.WithHandshakeTimeout(handshakeTimeout),
	}

	if readOnly {
		serverOptions = append(serverOptions, sftp.ReadOnly())
		fmt.Fprintf(debugStream, "Read-only server for %q\n", username)
	} else {
		fmt.Fprintf(debugStream, "Read write server for %q\n", username)
	}

	if winRoot {
		serverOptions = append(serverOptions, sftp.WindowsRootEnumeratesDrives())
		fmt.Fprintf(debugStream, "Windows root enabled for %q\n", username)
	}

	server, err := sftp.NewServer(channel, serverOptions...)
	if err != nil {
		log.Printf("failed to create SFTP server for %q: %v", username, err)
		return true
	}
	defer server.Close()

	err = server.Serve()
	if err == io.EOF {
		err = nil
	}

	// Like sshd, tell the client how the subsystem exited before closing the channel.
	// Some clients wait for this before they consider the session finished.
	exitStatus := uint32(0)
	if err != nil {
		exitStatus = 1
	}
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{exitStatus}))

	if err != nil {
		log.Printf("sftp server for %q completed with error: %v", username, err)
	} else {
		log.Printf("sftp client %q exited session", username)
	}
	return true
}
