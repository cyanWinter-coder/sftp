package sftp

import "net"

// Listener accepts network connections and serves one independently-managed
// SFTP Server for each accepted connection.
type Listener struct {
	net.Listener
	manager *ConnectionManager
}

// Listen creates a TCP listener and ConnectionManager configured with the
// supplied ServerOptions. Use Serve to start accepting SFTP connections.
func Listen(network, address string, options ...ServerOption) (*Listener, error) {
	listener, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}

	manager, err := NewConnectionManager(options...)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}

	return &Listener{Listener: listener, manager: manager}, nil
}

// Manager returns the connection manager used by this listener.
func (l *Listener) Manager() *ConnectionManager { return l.manager }

// ActiveConnections returns the number of live SFTP connections.
func (l *Listener) ActiveConnections() int { return l.manager.Active() }

// Serve accepts and serves connections until the underlying listener is
// closed.
func (l *Listener) Serve() error {
	return l.manager.Serve(l.Listener)
}

// Close stops accepting connections and closes all active connections.
func (l *Listener) Close() error {
	listenerErr := l.Listener.Close()
	managerErr := l.manager.Close()
	if listenerErr != nil {
		return listenerErr
	}
	return managerErr
}

// ListenAndServe listens and serves SFTP until the listener stops.
func ListenAndServe(network, address string, options ...ServerOption) error {
	listener, err := Listen(network, address, options...)
	if err != nil {
		return err
	}
	defer listener.Close()
	return listener.Serve()
}
