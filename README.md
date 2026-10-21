# e2e-chat

A simple command-line chat app where two people can talk privately over a network. All messages are end-to-end encrypted — the relay server only sees ciphertext and has no way to read anything.

Built in Go, no external dependencies except `golang.org/x/crypto`.

---

## How it works

There are two parts:

- **Server** — a lightweight TCP relay. It pairs two clients in the same room and forwards encrypted frames between them. That's it. It never touches the message content.
- **Client** — connects to the server, does a key exchange with the other person, then sends and receives encrypted messages from the terminal.

The encryption flow:
1. Each client generates a fresh **X25519** key pair on startup
2. Public keys are exchanged through the server (the server sees these — that's fine, they're public)
3. Both sides compute the same **shared secret** using Diffie-Hellman
4. The shared secret is passed through **HKDF-SHA256** to derive a 32-byte **AES-256-GCM** key
5. Every message is encrypted with a random nonce before being sent

The server never has the key. Even if someone was sniffing the traffic, they'd only see encrypted bytes.

---

## Build

You need Go 1.21+.

```bash
git clone https://github.com/elyessmida/e2e-chat.git
cd e2e-chat
go build -o server ./cmd/server
go build -o client ./cmd/client
```

---

## Usage

**Start the relay server** (on any machine, or just localhost for testing):
```bash
./server -addr :9000
```

**First person connects:**
```bash
./client -server localhost:9000 -room secretroom -name Alice
```

**Second person connects** (same room name):
```bash
./client -server localhost:9000 -room secretroom -name Bob
```

Once both are in, the key exchange happens automatically and the chat starts. Type `/quit` to exit.

The room name acts like a shared secret to find each other — pick something only the two of you know.

---

## Project structure

```
e2e-chat/
├── cmd/
│   ├── server/main.go       relay server
│   └── client/main.go       CLI client
└── internal/
    ├── crypto/crypto.go      X25519, HKDF, AES-256-GCM
    └── framing/framing.go    length-prefixed frame I/O
```

---

## Notes

- Keys are ephemeral — a new key pair is generated every session. There's no persistent identity or certificate pinning, so this is not resistant to a MITM attack if someone controls the relay server. For casual private use between two people who trust the server, it's fine.
- The server can run on any VPS or even just your own machine if both people are on the same network.
- Windows, Linux, Mac — works on all three.

---

## Stack

- **Language:** Go
- **Key exchange:** X25519 (Curve25519)
- **Key derivation:** HKDF-SHA256
- **Encryption:** AES-256-GCM
- **Transport:** raw TCP with length-prefixed framing
