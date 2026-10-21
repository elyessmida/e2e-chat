// client is the CLI frontend for e2e-chat.
//
// Workflow:
//  1. Connect to the server via TCP.
//  2. Send a ROOM frame with the desired room ID.
//  3. Generate an X25519 ephemeral key pair; send the public key as a KEY frame.
//  4. Wait for the peer's KEY frame; perform X25519 + HKDF to derive the
//     shared AES-256-GCM key.
//  5. Launch two goroutines:
//     - receiver: reads framed messages from the server, decrypts, and prints.
//     - sender (main goroutine): reads stdin lines, encrypts, and sends.
//
// All message frames after key exchange are:
//
//	"MSG:" (4 bytes) | 12-byte nonce | AES-256-GCM ciphertext
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/local/e2e-chat/internal/crypto"
	"github.com/local/e2e-chat/internal/framing"
)

// Frame type tags (4 ASCII bytes each).
const (
	tagROOM = "ROOM"
	tagKEY  = "KEY:"
	tagMSG  = "MSG:"
	tagBYE  = "BYE:"
)

func main() {
	// ---------------------------------------------------------------
	// Parse CLI flags: -server, -room, -name
	// ---------------------------------------------------------------
	serverAddr := flag.String("server", "localhost:9000", "relay server address (host:port)")
	roomID     := flag.String("room", "default", "room ID to join")
	name       := flag.String("name", "Me", "your display name")
	flag.Parse()

	_ = *name // used in prompt below

	// ---------------------------------------------------------------
	// Connect to server.
	// ---------------------------------------------------------------
	conn, err := net.Dial("tcp", *serverAddr)
	if err != nil {
		fatalf("connect to %s: %v", *serverAddr, err)
	}
	defer conn.Close()
	infof("Connected to server at %s", *serverAddr)

	// ---------------------------------------------------------------
	// Step 1: Send ROOM frame.
	// ---------------------------------------------------------------
	if err := framing.WriteFrame(conn, []byte(tagROOM+*roomID)); err != nil {
		fatalf("send ROOM: %v", err)
	}
	infof("Waiting for peer in room %q...", *roomID)

	// ---------------------------------------------------------------
	// Step 2: Generate X25519 key pair and send public key.
	// ---------------------------------------------------------------
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		fatalf("key generation: %v", err)
	}

	// KEY frame = "KEY:" + 32 raw bytes of public key.
	keyFrame := make([]byte, 4+32)
	copy(keyFrame[:4], tagKEY)
	copy(keyFrame[4:], kp.Public[:])
	if err := framing.WriteFrame(conn, keyFrame); err != nil {
		fatalf("send KEY: %v", err)
	}

	// ---------------------------------------------------------------
	// Step 3: Receive peer's public key.
	// ---------------------------------------------------------------
	frame, err := framing.ReadFrame(conn)
	if err != nil {
		fatalf("read peer KEY: %v", err)
	}
	if len(frame) < 4+32 || string(frame[:4]) != tagKEY {
		fatalf("expected KEY frame, got %q", frame[:min(len(frame), 8)])
	}

	var peerPub [32]byte
	copy(peerPub[:], frame[4:36])

	// ---------------------------------------------------------------
	// Step 4: Derive shared AES-256 key via X25519 + HKDF-SHA256.
	// ---------------------------------------------------------------
	sharedKey, err := crypto.DeriveSharedKey(kp.Private, peerPub)
	if err != nil {
		fatalf("key derivation: %v", err)
	}
	infof("Peer connected! Key exchange done. Chat is now E2E encrypted.")
	fmt.Println("  Type a message and press Enter. Use /quit to exit.")
	fmt.Println(strings.Repeat("-", 50))

	// done is closed when either side wants to terminate the session.
	done := make(chan struct{})

	// ---------------------------------------------------------------
	// Receiver goroutine: read frames from server, decrypt, display.
	// ---------------------------------------------------------------
	go func() {
		for {
			frame, err := framing.ReadFrame(conn)
			if err != nil {
				select {
				case <-done:
					// Local /quit already triggered shutdown — stay quiet.
				default:
					printAboveLine("\r[!] Connection closed by server.\n")
				}
				close(done)
				return
			}

			if len(frame) < 4 {
				continue
			}
			tag := string(frame[:4])

			switch tag {
			case tagMSG:
				// MSG frame: [4-byte tag] [12-byte nonce] [ciphertext]
				encPayload := frame[4:]
				plaintext, err := crypto.Decrypt(sharedKey, encPayload)
				if err != nil {
					printAboveLine(fmt.Sprintf("\r[!] Decrypt error: %v\n", err))
					continue
				}
				printAboveLine(fmt.Sprintf("\rPeer: %s\n", string(plaintext)))

			case tagBYE:
				reason := string(frame[4:])
				printAboveLine(fmt.Sprintf("\r[*] %s\n", reason))
				close(done)
				return

			default:
				// Unexpected frame type — ignore.
			}
		}
	}()

	// ---------------------------------------------------------------
	// Sender (main goroutine): read stdin, encrypt, send.
	// ---------------------------------------------------------------
	scanner := bufio.NewScanner(os.Stdin)
	prompt := *name + ": "
	for {
		fmt.Print(prompt)
		if !scanner.Scan() {
			// stdin closed (Ctrl-D / pipe end).
			break
		}

		// Check whether the receiver goroutine has already closed the session.
		select {
		case <-done:
			fmt.Println("[*] Session ended.")
			return
		default:
		}

		line := scanner.Text()
		if line == "/quit" {
			infof("Exiting.")
			break
		}
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Encrypt the message.
		ciphertext, err := crypto.Encrypt(sharedKey, []byte(line))
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Encrypt error: %v\n", err)
			continue
		}

		// Build MSG frame: "MSG:" + [nonce+ciphertext].
		msgFrame := make([]byte, 4+len(ciphertext))
		copy(msgFrame[:4], tagMSG)
		copy(msgFrame[4:], ciphertext)

		if err := framing.WriteFrame(conn, msgFrame); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Send error: %v\n", err)
			break
		}
	}
}

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------

// infof prints a status line prefixed with [*].
func infof(format string, args ...any) {
	fmt.Printf("[*] "+format+"\n", args...)
}

// fatalf prints an error message and exits with code 1.
func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[!] "+format+"\n", args...)
	os.Exit(1)
}

// printAboveLine clears the current "You: " prompt line using \r, prints the
// message, then re-prints the prompt on the next line. This gives a basic
// split-view feel without requiring a full TUI library.
func printAboveLine(msg string) {
	// \r moves to the start of the current line, overwriting the "You: " prompt.
	fmt.Print(msg)
	fmt.Print("You: ")
}

// min returns the smaller of a and b (Go 1.21 has a built-in, kept for clarity).
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
