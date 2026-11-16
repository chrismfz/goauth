package goauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// softAuthenticator is a minimal software passkey: one ES256 credential,
// "none" attestation. Enough to run real registration and login ceremonies
// through the handlers.
type softAuthenticator struct {
	t         *testing.T
	key       *ecdsa.PrivateKey
	credID    []byte
	signCount uint32
	// flags sent in authenticator data, besides "attested data" at
	// registration. 0x01 user present, 0x04 user verified, 0x08 backup
	// eligible, 0x10 backed up.
	flags byte
}

const (
	testRPID   = "example.com"
	testOrigin = "https://example.com"
)

func newSoftAuthenticator(t *testing.T, flags byte) *softAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	rand.Read(id)
	return &softAuthenticator{t: t, key: key, credID: id, flags: flags}
}

var b64 = base64.RawURLEncoding

func (a *softAuthenticator) authData(extra byte, attested []byte) []byte {
	rp := sha256.Sum256([]byte(testRPID))
	out := append([]byte{}, rp[:]...)
	out = append(out, a.flags|extra)
	a.signCount++
	out = binary.BigEndian.AppendUint32(out, a.signCount)
	return append(out, attested...)
}

func clientData(typ, challenge string) []byte {
	raw, _ := json.Marshal(map[string]string{"type": typ, "challenge": challenge, "origin": testOrigin})
	return raw
}

func challengeOf(t *testing.T, body []byte) string {
	t.Helper()
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(body, &opts); err != nil || opts.PublicKey.Challenge == "" {
		t.Fatalf("no challenge in %s (%v)", body, err)
	}
	return opts.PublicKey.Challenge
}

// attestation answers a registration challenge.
func (a *softAuthenticator) attestation(options []byte) []byte {
	a.t.Helper()
	pad := func(b []byte) []byte { return append(make([]byte, 32-len(b)), b...) }
	cose, err := cbor.Marshal(map[int]any{
		1: 2, 3: -7, -1: 1,
		-2: pad(a.key.X.Bytes()), -3: pad(a.key.Y.Bytes()),
	})
	if err != nil {
		a.t.Fatal(err)
	}
	attested := make([]byte, 16) // AAGUID
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(a.credID)))
	attested = append(attested, a.credID...)
	attested = append(attested, cose...)

	attObj, err := cbor.Marshal(map[string]any{
		"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(0x40, attested),
	})
	if err != nil {
		a.t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.credID), "rawId": b64.EncodeToString(a.credID), "type": "public-key",
		"response": map[string]string{
			"clientDataJSON":    b64.EncodeToString(clientData("webauthn.create", challengeOf(a.t, options))),
			"attestationObject": b64.EncodeToString(attObj),
		},
	})
	return raw
}

// assertion answers a login challenge.
func (a *softAuthenticator) assertion(options []byte) []byte {
	a.t.Helper()
	cd := clientData("webauthn.get", challengeOf(a.t, options))
	ad := a.authData(0, nil)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		a.t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.credID), "rawId": b64.EncodeToString(a.credID), "type": "public-key",
		"response": map[string]string{
			"clientDataJSON":    b64.EncodeToString(cd),
			"authenticatorData": b64.EncodeToString(ad),
			"signature":         b64.EncodeToString(sig),
		},
	})
	return raw
}

// registerPasskey registers a on the logged-in client's own account.
func registerPasskey(t *testing.T, c *testClient, a *softAuthenticator, password string) {
	t.Helper()
	m := c.m
	rec := c.do(m.Require()(m.selfWebAuthnRegistrationBeginHandler()), http.MethodPost, "/begin", map[string]string{"password": password})
	if rec.Code != http.StatusOK {
		t.Fatalf("registration begin = %d %s", rec.Code, rec.Body.String())
	}
	rec = c.do(m.Require()(m.selfWebAuthnRegistrationFinishHandler()), http.MethodPost, "/finish", a.attestation(rec.Body.Bytes()))
	if rec.Code != http.StatusOK {
		t.Fatalf("registration finish = %d %s", rec.Code, rec.Body.String())
	}
}

// passkeyMFALogin does password + passkey and returns the finish response.
func passkeyMFALogin(t *testing.T, m *Manager, a *softAuthenticator) (*testClient, int, string) {
	t.Helper()
	c := newTestClient(t, m)
	if rec := c.login("alice", testPassword); !strings.Contains(rec.Body.String(), "mfa_required") {
		t.Fatalf("password step: %d %s", rec.Code, rec.Body.String())
	}
	rec := c.do(m.WebAuthnLoginBeginHandler(), http.MethodPost, "/login/webauthn/begin", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login begin = %d %s", rec.Code, rec.Body.String())
	}
	rec = c.do(m.WebAuthnLoginFinishHandler(), http.MethodPost, "/login/webauthn/finish", a.assertion(rec.Body.Bytes()))
	return c, rec.Code, rec.Body.String()
}

func setupPasskeyUser(t *testing.T, flags byte) (*Manager, *softAuthenticator) {
	t.Helper()
	m := newTestWebAuthnManager(t)
	mustCreate(t, m, "alice", testPassword)
	c := newTestClient(t, m)
	c.login("alice", testPassword)
	enrollTOTP(t, c) // turns MFA on, so a passkey can be the second factor
	a := newSoftAuthenticator(t, flags)
	registerPasskey(t, c, a, testPassword)
	return m, a
}

func TestPasskeyAsSecondFactorEndToEnd(t *testing.T) {
	for name, flags := range map[string]byte{
		"device-bound key":       0x01 | 0x04,
		"synced passkey (BE+BS)": 0x01 | 0x04 | 0x08 | 0x10,
	} {
		t.Run(name, func(t *testing.T) {
			m, a := setupPasskeyUser(t, flags)
			defer m.Close()
			for i := 0; i < 2; i++ { // the second login runs against the stored flags
				c, code, body := passkeyMFALogin(t, m, a)
				if code != http.StatusOK {
					t.Fatalf("login %d finish = %d %s", i, code, body)
				}
				if ok, _ := c.authed(); !ok {
					t.Fatalf("login %d: session not accepted after a passkey login", i)
				}
			}
			var stored int64
			if err := m.db.QueryRow(`SELECT flags FROM webauthn_credentials`).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			if got := decodeCredentialFlags(stored).BackupEligible; got != (flags&0x08 != 0) {
				t.Fatalf("stored backup-eligible = %v, authenticator says %v", got, flags&0x08 != 0)
			}
		})
	}
}

// A synced passkey registered before flags were stored has none on record.
// It must keep working, and its flags must be on record afterwards.
func TestSyncedPasskeyStoredWithoutFlagsStillLogsIn(t *testing.T) {
	m, a := setupPasskeyUser(t, 0x01|0x04|0x08|0x10)
	defer m.Close()
	if _, err := m.db.Exec(`UPDATE webauthn_credentials SET flags=NULL`); err != nil {
		t.Fatal(err)
	}
	if _, code, body := passkeyMFALogin(t, m, a); code != http.StatusOK {
		t.Fatalf("login with a flag-less stored credential = %d %s", code, body)
	}
	var flags *int64
	if err := m.db.QueryRow(`SELECT flags FROM webauthn_credentials`).Scan(&flags); err != nil {
		t.Fatal(err)
	}
	if flags == nil || !decodeCredentialFlags(*flags).BackupEligible {
		t.Fatalf("flags after login = %v, want backup-eligible on record", flags)
	}
}

// Once flags are on record, an assertion that disagrees on backup
// eligibility is a different authenticator and is refused.
func TestPasskeyWithChangedBackupEligibilityIsRefused(t *testing.T) {
	m, a := setupPasskeyUser(t, 0x01|0x04)
	defer m.Close()
	a.flags |= 0x08 | 0x10
	if _, code, _ := passkeyMFALogin(t, m, a); code != http.StatusUnauthorized {
		t.Fatalf("login with changed backup eligibility = %d, want 401", code)
	}
}

func TestPasskeyRegistrationNeedsReauthentication(t *testing.T) {
	m := newTestWebAuthnManager(t)
	defer m.Close()
	mustCreate(t, m, "alice", testPassword)
	c := newTestClient(t, m)
	c.login("alice", testPassword)
	begin := m.Require()(m.selfWebAuthnRegistrationBeginHandler())
	if rec := c.do(begin, http.MethodPost, "/begin", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("begin with a session alone = %d, want 401", rec.Code)
	}
	if rec := c.do(begin, http.MethodPost, "/begin", map[string]string{"password": "wrong"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("begin with a wrong password = %d, want 401", rec.Code)
	}
	if rec := c.do(begin, http.MethodPost, "/begin", map[string]string{"password": testPassword}); rec.Code != http.StatusOK {
		t.Fatalf("begin with the password = %d %s", rec.Code, rec.Body.String())
	}
}

// A passkey assertion with a bad signature must not log anyone in.
func TestPasskeyLoginRejectsAForgedAssertion(t *testing.T) {
	m, a := setupPasskeyUser(t, 0x01|0x04)
	defer m.Close()
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a.key = other // same credential id, someone else's key
	c, code, _ := passkeyMFALogin(t, m, a)
	if code != http.StatusUnauthorized {
		t.Fatalf("forged assertion = %d, want 401", code)
	}
	if ok, _ := c.authed(); ok {
		t.Fatal("forged assertion produced a session")
	}
}
