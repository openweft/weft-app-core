package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHForward reaches a DC's weft-webui by opening an SSH connection to a
// per-DC endpoint and forwarding to the webui's *internal* address from
// there (standard SSH direct-tcpip, the same as `ssh -L`). It is the
// zero-config transport : it needs no tun device and no VPN entitlement,
// so it works on locked-down corporate networks and on mobile.
//
// Authentication is the user's SSH key — the same identity weft already
// understands. The network boundary is the SSH server : weft-webui never
// has to listen on a public interface.
//
// The SSH client is established lazily and reused across Dials; if it
// drops, the next Dial/Probe transparently re-establishes it.
type SSHForward struct {
	// SSHAddr is "host:port" of the SSH endpoint for this DC.
	SSHAddr string
	// User for the SSH connection. Defaults to $USER when empty.
	User string
	// Signer authenticates the connection (the user's private key). If
	// nil, HostKeyCallback-only configs will fail — callers normally set
	// this via LoadSigner.
	Signer ssh.Signer
	// HostKey verifies the server. Use ssh.FixedHostKey in production; a
	// nil value rejects all connections (fail closed).
	HostKey ssh.HostKeyCallback
	// WebUIAddr is the webui listener address as seen *from the SSH host*,
	// e.g. "127.0.0.1:8443" or a mesh IP. This is what gets forwarded to.
	WebUIAddr string
	// DialTimeout bounds the SSH handshake and each forward. Zero means 5s.
	DialTimeout time.Duration

	mu     sync.Mutex
	client *ssh.Client
}

func (s *SSHForward) timeout() time.Duration {
	if s.DialTimeout <= 0 {
		return 5 * time.Second
	}
	return s.DialTimeout
}

func (s *SSHForward) user() string {
	if s.User != "" {
		return s.User
	}
	return os.Getenv("USER")
}

// connect returns a live ssh.Client, dialing a new one if necessary.
func (s *SSHForward) connect(ctx context.Context) (*ssh.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != nil {
		return s.client, nil
	}
	hostKey := s.HostKey
	if hostKey == nil {
		// Fail closed: refuse to connect without server verification.
		return nil, fmt.Errorf("ssh forward %s: no host key callback configured", s.SSHAddr)
	}
	cfg := &ssh.ClientConfig{
		User:            s.user(),
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(s.Signer)},
		HostKeyCallback: hostKey,
		Timeout:         s.timeout(),
	}
	raw, err := (&net.Dialer{Timeout: s.timeout()}).DialContext(ctx, "tcp", s.SSHAddr)
	if err != nil {
		return nil, fmt.Errorf("ssh dial %s: %w", s.SSHAddr, err)
	}
	conn, chans, reqs, err := ssh.NewClientConn(raw, s.SSHAddr, cfg)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("ssh handshake %s: %w", s.SSHAddr, err)
	}
	s.client = ssh.NewClient(conn, chans, reqs)
	return s.client, nil
}

// dropClient tears down the cached client so the next call reconnects.
func (s *SSHForward) dropClient() {
	s.mu.Lock()
	c := s.client
	s.client = nil
	s.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

func (s *SSHForward) Dial(ctx context.Context) (net.Conn, error) {
	client, err := s.connect(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := client.DialContext(ctx, "tcp", s.WebUIAddr)
	if err != nil {
		// The cached client may be stale; drop it so the next attempt
		// re-handshakes rather than reusing a dead channel.
		s.dropClient()
		return nil, fmt.Errorf("ssh forward to %s: %w", s.WebUIAddr, err)
	}
	return conn, nil
}

func (s *SSHForward) Probe(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	conn, err := s.Dial(ctx)
	if err != nil {
		return err
	}
	return conn.Close()
}

func (s *SSHForward) Target() string {
	return fmt.Sprintf("ssh://%s/%s", s.SSHAddr, s.WebUIAddr)
}

func (s *SSHForward) Close() error {
	s.dropClient()
	return nil
}

// LoadSigner reads a PEM private key from path and returns an ssh.Signer.
// Equivalent to LoadSignerWithPassphrase(path, nil) — convenience for
// callers who know the key is unencrypted.
func LoadSigner(path string) (ssh.Signer, error) {
	return LoadSignerWithPassphrase(path, nil)
}

// PassphraseFunc returns the passphrase that decrypts the private key
// at the given path. Called only when the key is encrypted ; nil means
// "no source available", which surfaces *ssh.PassphraseMissingError to
// the caller as before.
//
// The intended platform implementation (weft-app-osx) looks the
// passphrase up in macOS Keychain (service=weft-ssh-passphrase,
// account=<canonical key path>), gated by the system's standard
// authentication UI. The caller can pre-stage the entry via the
// app's `--store-ssh-passphrase <path>` flag.
type PassphraseFunc func(keyPath string) ([]byte, error)

// LoadSignerWithPassphrase reads a PEM private key from path. If the
// key is encrypted, passphraseFn is called to obtain the passphrase ;
// passing nil means "fail on encrypted keys" (the legacy LoadSigner
// behaviour).
func LoadSignerWithPassphrase(path string, passphraseFn PassphraseFunc) (ssh.Signer, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ssh key %s: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err == nil {
		return signer, nil
	}
	// Encrypted key — try the passphrase source.
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		return nil, fmt.Errorf("parse ssh key %s: %w", path, err)
	}
	if passphraseFn == nil {
		return nil, fmt.Errorf("ssh key %s is passphrase-protected ; no passphrase source configured (use `weft-app-osx --store-ssh-passphrase %s` to cache one in Keychain)", path, path)
	}
	passphrase, err := passphraseFn(path)
	if err != nil {
		return nil, fmt.Errorf("get passphrase for %s: %w", path, err)
	}
	signer, err = ssh.ParsePrivateKeyWithPassphrase(pem, passphrase)
	if err != nil {
		return nil, fmt.Errorf("decrypt ssh key %s: %w", path, err)
	}
	return signer, nil
}
