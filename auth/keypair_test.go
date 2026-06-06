package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestGenerateKeypairValid(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("private length = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public length = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	// Round-trip a sign to confirm the pair actually works.
	msg := []byte("smoke")
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("generated keypair must round-trip a sign/verify")
	}
}

func TestEncodeDecodePubKeyRoundTrip(t *testing.T) {
	_, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	enc := EncodePubKey(pub)
	if l := len(enc); l != 44 {
		t.Fatalf("encoded pubkey length = %d, want 44 (base64-std of 32B)", l)
	}
	got, err := DecodePubKey(enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(pub) {
		t.Fatal("round-trip pubkey mismatch")
	}
}

func TestDecodePubKeyBadInputs(t *testing.T) {
	if _, err := DecodePubKey("***not-base64***"); err == nil {
		t.Fatal("non-base64 should error")
	}
	// Valid base64 of the wrong length.
	short := base64.StdEncoding.EncodeToString([]byte{1, 2, 3})
	if _, err := DecodePubKey(short); err == nil {
		t.Fatal("short pubkey should error")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	const aud = "https://weft.example/api/auth/keypair"
	jws, err := SignAssertion(priv, aud)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	claims, err := VerifyAssertion(jws, aud)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Aud != aud {
		t.Fatalf("aud mismatch: %q", claims.Aud)
	}
	if claims.Iss != "weft-app-osx" {
		t.Fatalf("iss = %q, want weft-app-osx", claims.Iss)
	}
	if claims.Sub == "" {
		t.Fatal("sub must hold the encoded pubkey")
	}
	if claims.Nonce == "" {
		t.Fatal("nonce must be populated")
	}
	if claims.Iat <= 0 || claims.Exp <= claims.Iat {
		t.Fatalf("iat/exp invalid: iat=%d exp=%d", claims.Iat, claims.Exp)
	}
}

func TestSignAssertionRejectsBadInputs(t *testing.T) {
	priv, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignAssertion(priv, ""); err == nil {
		t.Fatal("empty audience should error")
	}
	// Truncated private key.
	if _, err := SignAssertion(priv[:10], "aud"); err == nil {
		t.Fatal("short private key should error")
	}
}

func TestVerifyRejectsEmptyAllowedAudience(t *testing.T) {
	priv, _, _ := GenerateKeypair()
	jws, _ := SignAssertion(priv, "aud")
	if _, err := VerifyAssertion(jws, ""); err == nil {
		t.Fatal("empty allowedAudience should error")
	}
}

func TestVerifyRejectsAudienceMismatch(t *testing.T) {
	priv, _, _ := GenerateKeypair()
	jws, _ := SignAssertion(priv, "aud-a")
	if _, err := VerifyAssertion(jws, "aud-b"); err == nil {
		t.Fatal("audience mismatch should error")
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	priv, _, _ := GenerateKeypair()
	pub := priv.Public().(ed25519.PublicKey)
	claims := AssertionClaims{
		Iss:   "weft-app-osx",
		Sub:   EncodePubKey(pub),
		Aud:   "aud",
		Iat:   time.Now().Add(-2 * time.Hour).Unix(),
		Exp:   time.Now().Add(-time.Hour).Unix(),
		Nonce: "n",
	}
	jws := craftJWS(t, priv, claims)
	if _, err := VerifyAssertion(jws, "aud"); err == nil {
		t.Fatal("expired assertion must fail")
	}
}

func TestVerifyRejectsFutureIat(t *testing.T) {
	priv, _, _ := GenerateKeypair()
	pub := priv.Public().(ed25519.PublicKey)
	claims := AssertionClaims{
		Iss:   "weft-app-osx",
		Sub:   EncodePubKey(pub),
		Aud:   "aud",
		Iat:   time.Now().Add(time.Hour).Unix(),
		Exp:   time.Now().Add(2 * time.Hour).Unix(),
		Nonce: "n",
	}
	jws := craftJWS(t, priv, claims)
	if _, err := VerifyAssertion(jws, "aud"); err == nil {
		t.Fatal("iat-in-the-future must fail")
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	priv, _, _ := GenerateKeypair()
	jws, _ := SignAssertion(priv, "aud")
	parts := strings.Split(string(jws), ".")
	if len(parts) != 3 {
		t.Fatalf("want 3 segments, got %d", len(parts))
	}
	// Re-encode the payload with a different audience while keeping the
	// original signature : verify must catch the mismatch.
	body, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c AssertionClaims
	_ = json.Unmarshal(body, &c)
	c.Aud = "evil-aud"
	tampered, _ := json.Marshal(c)
	parts[1] = base64.RawURLEncoding.EncodeToString(tampered)
	bad := Assertion(strings.Join(parts, "."))
	if _, err := VerifyAssertion(bad, "aud"); err == nil {
		t.Fatal("tampered payload must fail signature check")
	}
}

func TestVerifyRejectsMalformedSegments(t *testing.T) {
	if _, err := VerifyAssertion("only-two.segments", "aud"); err == nil {
		t.Fatal("two-segment JWS must fail")
	}
	if _, err := VerifyAssertion("a.b.c", "aud"); err == nil {
		t.Fatal("garbage base64 must fail")
	}
}

func TestVerifyRejectsBadAlg(t *testing.T) {
	priv, _, _ := GenerateKeypair()
	pub := priv.Public().(ed25519.PublicKey)
	// Hand-craft a JWS with alg="none" — verifier must refuse without
	// even attempting a signature check.
	hdr, _ := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	claims, _ := json.Marshal(AssertionClaims{
		Iss: "weft-app-osx", Sub: EncodePubKey(pub), Aud: "aud",
		Iat: time.Now().Unix(), Exp: time.Now().Add(time.Minute).Unix(),
	})
	sig := make([]byte, ed25519.SignatureSize)
	_, _ = rand.Read(sig)
	jws := Assertion(base64.RawURLEncoding.EncodeToString(hdr) + "." +
		base64.RawURLEncoding.EncodeToString(claims) + "." +
		base64.RawURLEncoding.EncodeToString(sig))
	if _, err := VerifyAssertion(jws, "aud"); err == nil {
		t.Fatal("alg=none must fail")
	}
}

func TestVerifyRejectsBadSignatureLength(t *testing.T) {
	priv, _, _ := GenerateKeypair()
	pub := priv.Public().(ed25519.PublicKey)
	hdr, _ := json.Marshal(header{Alg: "EdDSA", Typ: "JWT"})
	claims, _ := json.Marshal(AssertionClaims{
		Iss: "weft-app-osx", Sub: EncodePubKey(pub), Aud: "aud",
		Iat: time.Now().Unix(), Exp: time.Now().Add(time.Minute).Unix(),
	})
	short := []byte{1, 2, 3}
	jws := Assertion(base64.RawURLEncoding.EncodeToString(hdr) + "." +
		base64.RawURLEncoding.EncodeToString(claims) + "." +
		base64.RawURLEncoding.EncodeToString(short))
	if _, err := VerifyAssertion(jws, "aud"); err == nil {
		t.Fatal("short signature must fail")
	}
}

// craftJWS signs an arbitrary set of claims with priv ; used by the
// expiry / future-iat tests to bypass SignAssertion's "now" defaults.
func craftJWS(t *testing.T, priv ed25519.PrivateKey, claims AssertionClaims) Assertion {
	t.Helper()
	hdrJSON, err := json.Marshal(header{Alg: "EdDSA", Typ: "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hdrJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)
	sig := ed25519.Sign(priv, []byte(signingInput))
	return Assertion(signingInput + "." + base64.RawURLEncoding.EncodeToString(sig))
}

func TestAssertionStringPassthrough(t *testing.T) {
	if Assertion("abc.def.ghi").String() != "abc.def.ghi" {
		t.Fatal("String() must pass through")
	}
}
