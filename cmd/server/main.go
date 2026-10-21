// server is the TCP relay for e2e-chat.
//
// It accepts pairs of clients that identify the same room ID. After pairing,
// it blindly forwards every length-prefixed frame from client A to client B
// and vice-versa. It never inspects the payload, so all traffic (including
// plaintext key-exchange public keys and AES-256-GCM ciphertext) is treated
// identically.
//
// Wire flow:
//
//  1. Client connects.
//  2. Client sends framed message: "ROOM" + <room-name bytes>.
//  3. Server waits until a second client sends the same room ID.
//  4. Server goroutines relay frames between the two clients until one
//     disconnects.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/local/e2e-chat/internal/framing"
)

// room holds the two connections that belong to a room.
type room struct {
	clientA net.Conn
	// ready is closed once clientB also joins, unblocking clientA's relay loop.
	ready chan struct{}
	// clientB is set (under mu) when the second peer arrives.
	clientB net.Conn
	mu      sync.Mutex
}

// server manages active rooms.
type server struct {
	mu    sync.Mutex
	rooms map[string]*room
}

func newServer() *server {
	return &server{rooms: make(map[string]*room)}
}

// handleConn is called in a goroutine for every incoming connection.
func (s *server) handleConn(conn net.Conn) {
	defer conn.Close()

	addr := conn.RemoteAddr().String()
	log.Printf("[+] Client connected: %s", addr)

	// ---------------------------------------------------------------
	// Step 1: read the ROOM frame to determine which room to join.
	// ---------------------------------------------------------------
	frame, err := framing.ReadFrame(conn)
	if err != nil {
		log.Printf("[-] %s: read ROOM frame: %v", addr, err)
		return
	}

	const roomTag = "ROOM"
	if len(frame) < len(roomTag) || string(frame[:len(roomTag)]) != roomTag {
		log.Printf("[-] %s: expected ROOM tag, got %q", addr, frame)
		return
	}
	roomID := strings.TrimSpace(string(frame[len(roomTag):]))
	if roomID == "" {
		log.Printf("[-] %s: empty room ID", addr)
		return
	}
	log.Printf("[*] %s joined room %q", addr, roomID)

	// ---------------------------------------------------------------
	// Step 2: register in the room map or pair with existing waiter.
	// ---------------------------------------------------------------
	s.mu.Lock()
	r, exists := s.rooms[roomID]
	if !exists {
		// First client in the room — create the room and wait.
		r = &room{
			clientA: conn,
			ready:   make(chan struct{}),
		}
		s.rooms[roomID] = r
		s.mu.Unlock()

		log.Printf("[*] Room %q: waiting for second peer...", roomID)
		// Block until the second peer arrives (or the connection closes).
		<-r.ready

		r.mu.Lock()
		peer := r.clientB
		r.mu.Unlock()

		if peer == nil {
			// clientA disconnected before clientB arrived; room already cleaned up.
			return
		}

		// Relay: A → B
		s.relay(conn, peer, roomID, "A→B")
	} else {
		// Second client — pair with the waiter.
		r.mu.Lock()
		r.clientB = conn
		r.mu.Unlock()
		close(r.ready) // wake up clientA

		// Remove the room from the map so a fresh pair can reuse the name.
		s.mu.Unlock()

		// Relay: B → A
		s.relay(conn, r.clientA, roomID, "B→A")

		// When B's relay returns, clean up the room entry.
		s.mu.Lock()
		delete(s.rooms, roomID)
		s.mu.Unlock()
	}

	log.Printf("[*] Room %q: relay finished for %s", roomID, addr)
}

// relay forwards every frame read from src to dst until src closes or errors.
// It also sends a special disconnect notice to dst when done.
func (s *server) relay(src, dst net.Conn, roomID, direction string) {
	log.Printf("[*] Room %q: relay started (%s)", roomID, direction)
	for {
		frame, err := framing.ReadFrame(src)
		if err != nil {
			if err == io.EOF || strings.Contains(err.Error(), "use of closed network connection") {
				log.Printf("[*] Room %q (%s): peer disconnected cleanly", roomID, direction)
			} else {
				log.Printf("[-] Room %q (%s): read error: %v", roomID, direction, err)
			}
			break
		}

		// Forward the frame verbatim to the other peer.
		if err := framing.WriteFrame(dst, frame); err != nil {
			log.Printf("[-] Room %q (%s): forward error: %v", roomID, direction, err)
			break
		}
	}

	// Notify the other peer that this side has gone away.
	// We use a special "BYE:" tag so the client can print a friendly message.
	_ = framing.WriteFrame(dst, []byte("BYE:peer disconnected"))
	dst.Close()
}

func main() {
	addr := flag.String("addr", ":9000", "address to listen on (e.g. :9000)")
	flag.Parse()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "server: listen %s: %v\n", *addr, err)
		os.Exit(1)
	}
	log.Printf("[*] e2e-chat server listening on %s", *addr)

	srv := newServer()
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[-] accept: %v", err)
			continue
		}
		go srv.handleConn(conn)
	}
}
