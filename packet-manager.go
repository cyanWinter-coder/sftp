package sftp

import (
	"encoding"
	"sort"
	"sync"
)

// The goal of the packetManager is to keep the outgoing packets in the same
// order as the incoming as is requires by section 7 of the RFC.

type packetManager struct {
	requests    chan orderedPacket
	responses   chan orderedPacket
	fini        chan struct{}
	incoming    orderedPackets
	outgoing    orderedPackets
	sender      packetSender // connection object
	working     *sync.WaitGroup
	packetCount uint32
	// onSendError, when non-nil, is invoked the first time sender.sendPacket
	// fails. It is the packetManager's only way to report a write error: the
	// controller is a single goroutine and cannot return one itself. Servers
	// wire it to conn.Close so a broken connection is torn down.
	onSendError func(error)
	// dead is set by the (single) controller goroutine after the first write
	// failure. Afterwards responses are only drained and discarded, never
	// written, so workers are never left blocked on the responses channel.
	dead bool
	// deadNotify is closed once, when dead flips to true. Tests synchronize on
	// it; production code uses onSendError instead.
	deadNotify chan struct{}
	// it is not nil if the allocator is enabled
	alloc *allocator
}

type packetSender interface {
	sendPacket(encoding.BinaryMarshaler) error
}

func newPktMgr(sender packetSender) *packetManager {
	s := &packetManager{
		requests:   make(chan orderedPacket, SftpServerWorkerCount),
		responses:  make(chan orderedPacket, SftpServerWorkerCount),
		fini:       make(chan struct{}),
		incoming:   make([]orderedPacket, 0, SftpServerWorkerCount),
		outgoing:   make([]orderedPacket, 0, SftpServerWorkerCount),
		sender:     sender,
		working:    &sync.WaitGroup{},
		deadNotify: make(chan struct{}),
	}
	go s.controller()
	return s
}

// // packet ordering
func (s *packetManager) newOrderID() uint32 {
	s.packetCount++
	return s.packetCount
}

// returns the next orderID without incrementing it.
// This is used before receiving a new packet, with the allocator enabled, to associate
// the slice allocated for the received packet with the orderID that will be used to mark
// the allocated slices for reuse once the request is served
func (s *packetManager) getNextOrderID() uint32 {
	return s.packetCount + 1
}

type orderedRequest struct {
	requestPacket
	orderid uint32
}

func (s *packetManager) newOrderedRequest(p requestPacket) orderedRequest {
	return orderedRequest{requestPacket: p, orderid: s.newOrderID()}
}
func (p orderedRequest) orderID() uint32 { return p.orderid }

type orderedResponse struct {
	responsePacket
	orderid uint32
}

func (s *packetManager) newOrderedResponse(p responsePacket, id uint32,
) orderedResponse {
	return orderedResponse{responsePacket: p, orderid: id}
}
func (p orderedResponse) orderID() uint32 { return p.orderid }

type orderedPacket interface {
	id() uint32
	orderID() uint32
}
type orderedPackets []orderedPacket

func (o orderedPackets) Sort() {
	sort.Slice(o, func(i, j int) bool {
		return o[i].orderID() < o[j].orderID()
	})
}

// // packet registry
// register incoming packets to be handled
func (s *packetManager) incomingPacket(pkt orderedRequest) {
	s.working.Add(1)
	s.requests <- pkt
}

// register outgoing packets as being ready
func (s *packetManager) readyPacket(pkt orderedResponse) {
	s.responses <- pkt
	s.working.Done()
}

// shut down packetManager controller
func (s *packetManager) close() {
	// pause until current packets are processed
	s.working.Wait()
	close(s.fini)
}

// Passed a worker function, returns a channel for incoming packets.
// Keep process packet responses in the order they are received while
// maximizing throughput of file transfers.
func (s *packetManager) workerChan(runWorker func(chan orderedRequest),
) chan orderedRequest {
	// multiple workers for faster read/writes
	rwChan := make(chan orderedRequest, SftpServerWorkerCount)
	for i := 0; i < SftpServerWorkerCount; i++ {
		runWorker(rwChan)
	}

	// single worker to enforce sequential processing of everything else
	cmdChan := make(chan orderedRequest)
	runWorker(cmdChan)

	pktChan := make(chan orderedRequest, SftpServerWorkerCount)
	go func() {
		for pkt := range pktChan {
			switch pkt.requestPacket.(type) {
			case *sshFxpReadPacket, *sshFxpWritePacket:
				s.incomingPacket(pkt)
				rwChan <- pkt
				continue
			case *sshFxpClosePacket:
				// wait for reads/writes to finish when file is closed
				// incomingPacket() call must occur after this
				s.working.Wait()
			}
			s.incomingPacket(pkt)
			// all non-RW use sequential cmdChan
			cmdChan <- pkt
		}
		close(rwChan)
		close(cmdChan)
		s.close()
	}()

	return pktChan
}

// process packets
func (s *packetManager) controller() {
	for {
		select {
		case pkt := <-s.requests:
			debug("incoming id (oid): %v (%v)", pkt.id(), pkt.orderID())
			s.incoming = append(s.incoming, pkt)
			s.incoming.Sort()
		case pkt := <-s.responses:
			debug("outgoing id (oid): %v (%v)", pkt.id(), pkt.orderID())
			s.outgoing = append(s.outgoing, pkt)
			s.outgoing.Sort()
		case <-s.fini:
			return
		}
		// Once a write has failed the connection is being torn down, but the
		// workers still need their responses drained; keep looping until fini.
		s.maybeSendPackets()
	}
}

// maybeSendPackets sends every response whose request has arrived, in request
// order. After the first write failure the manager switches to draining mode:
// queued pairs are discarded and every request's allocated pages are returned
// without touching the broken connection, so workers never block and no buffer
// leaks. Pages are released off the incoming queue, which works even when the
// matching response has not been queued yet (or never arrives).
func (s *packetManager) maybeSendPackets() {
	for {
		if len(s.incoming) == 0 {
			debug("break! -- outgoing: %v; incoming: %v",
				len(s.outgoing), len(s.incoming))
			return
		}
		in := s.incoming[0]

		// In draining mode drop every request that is queued, whether or not
		// its response has arrived, returning its pages so nothing is held.
		if s.dead {
			if s.alloc != nil {
				s.alloc.ReleasePages(in.orderID())
			}
			s.popIncomingHead()
			if len(s.outgoing) > 0 && s.outgoing[0].orderID() == in.orderID() {
				s.popOutgoingHead()
			}
			continue
		}

		if len(s.outgoing) == 0 {
			// No response ready yet for the oldest request; wait for it.
			return
		}
		out := s.outgoing[0]
		if in.orderID() != out.orderID() {
			return
		}

		debug("Sending packet: %v", out.id())
		if err := s.sender.sendPacket(out.(encoding.BinaryMarshaler)); err != nil {
			// The connection can no longer carry responses. Switch to draining
			// mode, release the pages of the request that failed and of
			// everything queued behind it, then signal the connection tear-down.
			s.dead = true
			debug("sftp: failed to send response packet: %v", err)
			s.dropAllIncoming()
			s.outgoing = s.outgoing[:0]
			close(s.deadNotify)
			if s.onSendError != nil {
				s.onSendError(err)
			}
			return
		}

		if s.alloc != nil {
			// mark for reuse the slices allocated for this request
			s.alloc.ReleasePages(in.orderID())
		}
		s.popIncomingHead()
		s.popOutgoingHead()
	}
}

// popIncomingHead removes the oldest queued request.
func (s *packetManager) popIncomingHead() {
	copy(s.incoming, s.incoming[1:])            // shift left
	s.incoming[len(s.incoming)-1] = nil         // clear last
	s.incoming = s.incoming[:len(s.incoming)-1] // remove last
}

// popOutgoingHead removes the oldest queued response.
func (s *packetManager) popOutgoingHead() {
	copy(s.outgoing, s.outgoing[1:])            // shift left
	s.outgoing[len(s.outgoing)-1] = nil         // clear last
	s.outgoing = s.outgoing[:len(s.outgoing)-1] // remove last
}

// dropAllIncoming returns every queued request's pages to the allocator and
// empties the incoming ordering queue. It is only called by the controller
// goroutine when the connection has just failed.
func (s *packetManager) dropAllIncoming() {
	if s.alloc != nil {
		for _, p := range s.incoming {
			s.alloc.ReleasePages(p.orderID())
		}
	}
	s.incoming = s.incoming[:0]
}

// func oids(o []orderedPacket) []uint32 {
// 	res := make([]uint32, 0, len(o))
// 	for _, v := range o {
// 		res = append(res, v.orderId())
// 	}
// 	return res
// }
// func ids(o []orderedPacket) []uint32 {
// 	res := make([]uint32, 0, len(o))
// 	for _, v := range o {
// 		res = append(res, v.id())
// 	}
// 	return res
// }
