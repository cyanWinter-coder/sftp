package sftp

import (
	"errors"

	"golang.org/x/crypto/ssh"
)

// WithSSHConnection records the authenticated username and remote address from
// an SSH handshake on this SFTP Server only. SFTP itself has no authentication
// or username packet; this option is the safe bridge from ssh.ServerConn (or
// another ssh.ConnMetadata implementation) to per-connection SFTP state.
func WithSSHConnection(conn ssh.ConnMetadata) ServerOption {
	return func(s *Server) error {
		if conn == nil {
			return errors.New("sftp: ssh connection metadata must not be nil")
		}

		s.lifecycle.setAuthenticated(conn.User(), true, nil)
		if remoteAddr := conn.RemoteAddr(); remoteAddr != nil {
			s.lifecycle.setRemoteAddr(remoteAddr.String())
		}
		return nil
	}
}

// WithSSHConn is an alias for WithSSHConnection.
func WithSSHConn(conn ssh.ConnMetadata) ServerOption {
	return WithSSHConnection(conn)
}

// WithConnMetadata is an alias for WithSSHConnection.
func WithConnMetadata(conn ssh.ConnMetadata) ServerOption {
	return WithSSHConnection(conn)
}
