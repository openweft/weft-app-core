// Package auth holds the desktop-side auth helpers that are not tied to
// any particular OS (Keychain / Credential Manager / GNOME Keyring).
//
// The ed25519 keypair helper lives here because it's a tiny stdlib
// piece of cryptography (EdDSA over base64url-encoded JWS segments) that
// every desktop binary — weft-app-osx today, weft-app-gtk and
// weft-app-windows tomorrow — needs to wire up the dev keypair-fallback
// auth flow. The matching server side lives in weft-webui (see
// internal/auth/keypair.go) and validates the same JWS using the public
// key embedded in the "sub" claim of the payload.
//
// Threat model + intent : this auth path is opt-in twice (client config
// `auth.keypair_fallback` AND server flag `--keypair-allowlist`) and is
// designed for the local-dev case where the dex / OIDC stack is still
// being brought up against a live 3-DC cluster. It is NOT a substitute
// for OIDC in production — the verifier on the server keeps the trust
// boundary at the allowlist : if a key isn't allowlisted the assertion
// is rejected regardless of how well-formed it is.
//
// The JWS produced here is intentionally hand-rolled (header + payload +
// signature, base64url-encoded, joined by '.') rather than pulling in a
// JWT library : the schema is locked, the algorithm is fixed (EdDSA),
// and the verifier on the server reads the exact same bytes back.
package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// AssertionTTL is how long a freshly-signed assertion stays valid. Kept
// short on purpose — the assertion travels over HTTPS to a single
// endpoint and is immediately exchanged for a session token, so a 60s
// window covers normal request latency + clock skew without giving an
// interceptor a replay window worth caring about.
const AssertionTTL = 60 * time.Second

// MaxClockSkew is the leeway granted to the verifier when checking the
// `iat` field. Same intent as AssertionTTL : tight enough that a stolen
// assertion can't be replayed long after capture, loose enough that a
// laptop with a slightly fast clock still works.
const MaxClockSkew = 30 * time.Second

// header is the fixed JWS header we emit. typ is "JWT" so naive
// inspection tools render the payload nicely ; alg is "EdDSA" so the
// server side dispatches to ed25519.Verify.
type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// AssertionClaims is the payload baked into the JWS. The pubkey is in
// Sub so the verifier can reproduce the signature check without an
// out-of-band key directory — the allowlist owns the trust decision,
// not the JWS layer.
type AssertionClaims struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Aud   string `json:"aud"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
	Nonce string `json:"nonce"`
}

// Assertion is the wire form : the dot-joined JWS string returned by
// SignAssertion and consumed by VerifyAssertion / the server endpoint.
// We model it as a named string so the type system surfaces the intent
// at every call site (no accidental confusion with a generic token).
type Assertion string

// String returns the wire form unchanged. Helpful so an Assertion can be
// dropped straight into an http.Request body.
func (a Assertion) String() string { return string(a) }

// issuer is the literal value carried in the JWS `iss` claim. It is NOT
// a verified identity — the allowlist on the server is what authorises
// a keypair. We pin it to a fixed string so the server can refuse
// assertions originating from an unexpected client family if it ever
// wants to (today's verifier accepts any iss).
const issuer = "weft-app-osx"

// GenerateKeypair returns a fresh ed25519 keypair. The private key is
// the canonical 64-byte form (seed || pubkey) ; the public key is the
// raw 32-byte form. Callers persist priv in the platform secret store
// and print pub for the operator to paste into the allowlist.
func GenerateKeypair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("keypair: generate: %w", err)
	}
	return priv, pub, nil
}

// EncodePubKey returns the base64-std-encoded form of a 32-byte ed25519
// public key. This is the exact string an operator pastes into the
// allowlist JSON (no PEM wrapping, no URL-safe variant).
func EncodePubKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// DecodePubKey is the inverse of EncodePubKey ; useful for the server
// side reading the allowlist + for tests round-tripping a key.
func DecodePubKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("keypair: decode pubkey: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("keypair: pubkey length = %d, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// SignAssertion produces the JWS for the keypair-fallback flow.
// audience is the absolute URL of the server endpoint that will consume
// it (typically "<gateway>/api/auth/keypair") ; the verifier rejects an
// audience mismatch so a leaked assertion can't be replayed against a
// different cluster.
func SignAssertion(priv ed25519.PrivateKey, audience string) (Assertion, error) {
	if l := len(priv); l != ed25519.PrivateKeySize {
		return "", fmt.Errorf("keypair: private key length = %d, want %d", l, ed25519.PrivateKeySize)
	}
	if audience == "" {
		return "", errors.New("keypair: empty audience")
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", errors.New("keypair: private key has no usable public half")
	}

	var nonceBuf [32]byte
	if _, err := rand.Read(nonceBuf[:]); err != nil {
		return "", fmt.Errorf("keypair: read nonce entropy: %w", err)
	}
	now := time.Now().UTC()
	claims := AssertionClaims{
		Iss:   issuer,
		Sub:   EncodePubKey(pub),
		Aud:   audience,
		Iat:   now.Unix(),
		Exp:   now.Add(AssertionTTL).Unix(),
		Nonce: base64.RawURLEncoding.EncodeToString(nonceBuf[:]),
	}

	hdrJSON, err := json.Marshal(header{Alg: "EdDSA", Typ: "JWT"})
	if err != nil {
		return "", fmt.Errorf("keypair: marshal header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("keypair: marshal claims: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(hdrJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)
	sig := ed25519.Sign(priv, []byte(signingInput))
	return Assertion(signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)), nil
}

// VerifyAssertion parses a JWS, checks the EdDSA signature using the
// pubkey embedded in the payload's `sub` claim, and returns the parsed
// claims on success. allowedAudience MUST match the assertion's `aud`
// exactly — an empty allowedAudience is a programming bug, not a
// "match anything" wildcard.
//
// The verifier does NOT trust the pubkey itself : that is the
// allowlist's job. This function only proves the JWS is internally
// consistent and within its validity window.
func VerifyAssertion(jws Assertion, allowedAudience string) (AssertionClaims, error) {
	if allowedAudience == "" {
		return AssertionClaims{}, errors.New("keypair: empty allowedAudience")
	}
	parts := strings.Split(string(jws), ".")
	if len(parts) != 3 {
		return AssertionClaims{}, errors.New("keypair: malformed JWS (want 3 segments)")
	}

	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return AssertionClaims{}, fmt.Errorf("keypair: decode header: %w", err)
	}
	var hdr header
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return AssertionClaims{}, fmt.Errorf("keypair: parse header: %w", err)
	}
	if hdr.Alg != "EdDSA" {
		return AssertionClaims{}, fmt.Errorf("keypair: unsupported alg %q", hdr.Alg)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return AssertionClaims{}, fmt.Errorf("keypair: decode payload: %w", err)
	}
	var claims AssertionClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return AssertionClaims{}, fmt.Errorf("keypair: parse payload: %w", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return AssertionClaims{}, fmt.Errorf("keypair: decode signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return AssertionClaims{}, fmt.Errorf("keypair: signature length = %d, want %d", len(sig), ed25519.SignatureSize)
	}

	pub, err := DecodePubKey(claims.Sub)
	if err != nil {
		return AssertionClaims{}, err
	}

	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
		return AssertionClaims{}, errors.New("keypair: bad signature")
	}

	if claims.Aud != allowedAudience {
		return AssertionClaims{}, fmt.Errorf("keypair: audience mismatch (want %q, got %q)", allowedAudience, claims.Aud)
	}

	now := time.Now().UTC()
	if claims.Exp <= 0 || time.Unix(claims.Exp, 0).Before(now) {
		return AssertionClaims{}, errors.New("keypair: assertion expired")
	}
	if claims.Iat > 0 {
		issuedAt := time.Unix(claims.Iat, 0)
		if issuedAt.After(now.Add(MaxClockSkew)) {
			return AssertionClaims{}, errors.New("keypair: iat in the future beyond clock skew")
		}
	}

	return claims, nil
}
