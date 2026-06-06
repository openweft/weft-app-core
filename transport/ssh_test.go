package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// directTCPIPMsg is the payload of a "direct-tcpip" channel open request.
type directTCPIPMsg struct {
	Raddr string
	Rport uint32
	Laddr string
	Lport uint32
}

// startEcho starts a TCP server that writes `reply` to every connection
// then closes it. Returns its address and a stop func.
func startEcho(t *testing.T, reply string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.WriteString(c, reply)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// startSSHServer starts an SSH server that accepts any public key and
// honours "direct-tcpip" channels by dialling the requested address.
// Returns its address, its host public key, and a stop func.
func startSSHServer(t *testing.T) (string, ssh.PublicKey, func()) {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSSH(c, cfg)
		}
	}()
	return ln.Addr().String(), hostSigner.PublicKey(), func() { ln.Close() }
}

func serveSSH(c net.Conn, cfg *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		c.Close()
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "direct-tcpip" {
			nc.Reject(ssh.UnknownChannelType, "only direct-tcpip")
			continue
		}
		var msg directTCPIPMsg
		if err := ssh.Unmarshal(nc.ExtraData(), &msg); err != nil {
			nc.Reject(ssh.ConnectionFailed, "bad payload")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(chReqs)
		go func() {
			defer ch.Close()
			remote, err := net.Dial("tcp", net.JoinHostPort(msg.Raddr, strconv.Itoa(int(msg.Rport))))
			if err != nil {
				return
			}
			defer remote.Close()
			go io.Copy(remote, ch)
			io.Copy(ch, remote)
		}()
	}
}

func clientSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestSSHForwardDialsThroughServer is the end-to-end seam: an SSHForward
// dials an echo server *through* an SSH server's direct-tcpip channel and
// reads back the echo — with the host key pinned (ssh.FixedHostKey).
func TestSSHForwardDialsThroughServer(t *testing.T) {
	echoAddr, stopEcho := startEcho(t, "served-by-ssh")
	defer stopEcho()
	sshAddr, hostKey, stopSSH := startSSHServer(t)
	defer stopSSH()

	fwd := &SSHForward{
		SSHAddr:   sshAddr,
		User:      "weft",
		Signer:    clientSigner(t),
		HostKey:   ssh.FixedHostKey(hostKey),
		WebUIAddr: echoAddr,
	}
	defer fwd.Close()

	if err := fwd.Probe(context.Background()); err != nil {
		t.Fatalf("probe: %v", err)
	}

	conn, err := fwd.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "served-by-ssh" {
		t.Fatalf("got %q want served-by-ssh", got)
	}
}

// TestSSHForwardRejectsWrongHostKey proves host-key verification: pinning a
// different key than the server presents makes Dial fail.
func TestSSHForwardRejectsWrongHostKey(t *testing.T) {
	sshAddr, _, stopSSH := startSSHServer(t)
	defer stopSSH()

	// A host key from a different server.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherSigner, _ := ssh.NewSignerFromKey(otherPriv)

	fwd := &SSHForward{
		SSHAddr:   sshAddr,
		User:      "weft",
		Signer:    clientSigner(t),
		HostKey:   ssh.FixedHostKey(otherSigner.PublicKey()),
		WebUIAddr: "127.0.0.1:9",
	}
	defer fwd.Close()

	if err := fwd.Probe(context.Background()); err == nil {
		t.Fatal("expected host-key mismatch to fail the handshake")
	}
}

func TestSSHForwardNoHostKeyFailsClosed(t *testing.T) {
	fwd := &SSHForward{SSHAddr: "127.0.0.1:1", User: "x", Signer: clientSigner(t), WebUIAddr: "127.0.0.1:1"}
	if err := fwd.Probe(context.Background()); err == nil {
		t.Fatal("expected failure when no host key callback configured")
	}
}
