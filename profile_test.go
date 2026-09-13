package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestJWSSignatureVerifiesAgainstItsOwnKey is the check that matters most in
// this file: a JWS this gateway signs has to be independently verifiable by
// something that knows nothing about how it was built, because that is
// exactly the position every real ACME server is in. Building a signer and a
// verifier from the same misunderstanding of the spec would pass a test that
// only calls jwsSign and checks the result parses.
//
// Covers both algorithms an account key can produce. ES256 is the one worth
// distrusting on sight: crypto.Signer.Sign returns an ASN.1 DER signature, and
// RFC 7518 §3.4 wants the raw concatenation of r and s. Shipping the DER bytes
// is the single most common way to build a JOSE encoder that verifies against
// nothing but its own decoder.
func TestJWSSignatureVerifiesAgainstItsOwnKey(t *testing.T) {
	t.Run("ES256", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		raw, err := jwsSign(key, "kid-123", "nonce-abc", "https://ca.example/order",
			map[string]string{"hello": "world"})
		if err != nil {
			t.Fatalf("jwsSign: %v", err)
		}

		var jws struct{ Protected, Payload, Signature string }
		if err := json.Unmarshal(raw, &jws); err != nil {
			t.Fatalf("the JWS is not valid JSON: %v", err)
		}

		var protected struct{ Alg, Kid, Nonce, URL string }
		decodeB64(t, jws.Protected, &protected)
		if protected.Alg != "ES256" || protected.Kid != "kid-123" ||
			protected.Nonce != "nonce-abc" || protected.URL != "https://ca.example/order" {
			t.Fatalf("protected header wrong: %+v", protected)
		}

		sigRaw, err := base64.RawURLEncoding.DecodeString(jws.Signature)
		if err != nil {
			t.Fatalf("signature is not base64url: %v", err)
		}
		if len(sigRaw) != 64 {
			t.Fatalf("ES256 over P-256 must be exactly 64 raw bytes (32+32); got %d. "+
				"A length of ~70-72 here would mean the ASN.1 DER form leaked through unconverted", len(sigRaw))
		}
		r := new(big.Int).SetBytes(sigRaw[:32])
		s := new(big.Int).SetBytes(sigRaw[32:])

		signingInput := jws.Protected + "." + jws.Payload
		sum := sha256.Sum256([]byte(signingInput))
		if !ecdsa.Verify(&key.PublicKey, sum[:], r, s) {
			t.Fatal("the signature does not verify against the key that supposedly produced it")
		}
	})

	t.Run("RS256", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		raw, err := jwsSign(key, "kid-456", "nonce-def", "https://ca.example/finalize",
			map[string]string{"csr": "ZGF0YQ"})
		if err != nil {
			t.Fatalf("jwsSign: %v", err)
		}
		var jws struct{ Protected, Payload, Signature string }
		if err := json.Unmarshal(raw, &jws); err != nil {
			t.Fatalf("not valid JSON: %v", err)
		}
		var protected struct{ Alg string }
		decodeB64(t, jws.Protected, &protected)
		if protected.Alg != "RS256" {
			t.Fatalf("expected RS256 for an RSA key, got %q", protected.Alg)
		}
		sig, err := base64.RawURLEncoding.DecodeString(jws.Signature)
		if err != nil {
			t.Fatalf("signature is not base64url: %v", err)
		}
		sum := sha256.Sum256([]byte(jws.Protected + "." + jws.Payload))
		if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
			t.Fatalf("signature does not verify: %v", err)
		}
	})
}

// TestAnUnsupportedCurveIsRefused. Generating a signature this gateway cannot
// correctly size (jwsEncodeSignature hardcodes nothing, but a claim of ES256
// against anything but P-256 would be a lie in the protected header) must fail
// loudly rather than send a JWS the CA will reject for a reason this gateway
// never explains.
func TestAnUnsupportedCurveIsRefused(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if _, err := jwsSign(key, "kid", "nonce", "https://ca.example/order", nil); err == nil {
		t.Fatal("a P-384 account key must be refused, not silently labelled ES256")
	}
}

// TestSignedPostRetriesOnBadNonce. Pebble's own test configuration rejects
// about one nonce in twenty deliberately, on the reasoning that a client which
// cannot survive that will not survive a busy CA either. This proves the
// retry path exists and stops after one attempt rather than looping forever
// against a CA that is genuinely broken.
func TestSignedPostRetriesOnBadNonce(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	nonceCount := 0
	postCount := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		nonceCount++
		w.Header().Set("Replay-Nonce", "nonce-"+string(rune('a'+nonceCount)))
	})
	mux.HandleFunc("/post", func(w http.ResponseWriter, r *http.Request) {
		postCount++
		if postCount == 1 {
			w.Header().Set("Content-Type", "application/problem+json")
			w.Header().Set("Replay-Nonce", "fresh-nonce")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"type":"urn:ietf:params:acme:error:badNonce","detail":"stale"}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	res, err := signedPostWithRetry(context.Background(), ts.Client(), key, "kid",
		ts.URL+"/nonce", ts.URL+"/post", map[string]string{"a": "b"})
	if err != nil {
		t.Fatalf("signedPostWithRetry: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("expected the retry to succeed with 201, got %d", res.StatusCode)
	}
	if postCount != 2 {
		t.Fatalf("expected exactly one retry (2 POSTs), got %d", postCount)
	}
	if nonceCount != 2 {
		t.Fatalf("expected a fresh nonce to be fetched for the retry, got %d nonce fetches", nonceCount)
	}
}

// TestSignedPostDoesNotRetryTwice. A CA that keeps saying badNonce is not a
// client-side problem this loop should paper over forever.
func TestSignedPostDoesNotRetryTwice(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
	})
	attempts := 0
	mux.HandleFunc("/post", func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"type":"urn:ietf:params:acme:error:badNonce"}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	res, err := signedPostWithRetry(context.Background(), ts.Client(), key, "kid",
		ts.URL+"/nonce", ts.URL+"/post", nil)
	if err != nil {
		t.Fatalf("signedPostWithRetry: %v", err)
	}
	defer res.Body.Close()
	if attempts != 2 {
		t.Fatalf("expected exactly one retry (2 attempts total) even though the CA kept failing, got %d", attempts)
	}
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("the second, un-retried failure must reach the caller, got %d", res.StatusCode)
	}
}

// TestFetchDirectoryMetaReadsProfiles.
func TestFetchDirectoryMetaReadsProfiles(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"newOrder": "https://ca.example/order",
			"newNonce": "https://ca.example/nonce",
			"meta": {"profiles": {"default": "the usual", "shortlived": "six days"}}
		}`))
	}))
	defer ts.Close()

	meta, err := fetchDirectoryMeta(context.Background(), ts.Client(), ts.URL)
	if err != nil {
		t.Fatalf("fetchDirectoryMeta: %v", err)
	}
	if len(meta.Meta.Profiles) != 2 || meta.Meta.Profiles["shortlived"] != "six days" {
		t.Fatalf("profiles not read correctly: %+v", meta.Meta.Profiles)
	}
}

// TestFetchDirectoryMetaOnACAWithNoProfiles returns an empty, non-nil map
// rather than an error — a CA that has not implemented the draft is not a
// failure, and the distinction matters to every caller: checkProfileAdvertised
// treats a non-nil empty map as "cannot judge, pass it through" rather than
// "nothing is ever valid".
func TestFetchDirectoryMetaOnACAWithNoProfiles(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"newOrder": "https://ca.example/order"}`))
	}))
	defer ts.Close()

	meta, err := fetchDirectoryMeta(context.Background(), ts.Client(), ts.URL)
	if err != nil {
		t.Fatalf("fetchDirectoryMeta: %v", err)
	}
	if meta.Meta.Profiles == nil {
		t.Fatal("Profiles must be non-nil even when the CA sent none, so callers can range over it unconditionally")
	}
	if len(meta.Meta.Profiles) != 0 {
		t.Fatalf("expected no profiles, got %v", meta.Meta.Profiles)
	}
}

// TestCheckProfileAdvertised.
func TestCheckProfileAdvertised(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"meta": {"profiles": {"default": "d", "shortlived": "s"}}}`))
	}))
	defer ts.Close()
	p := &Provider{httpClient: ts.Client()}
	cfg := &Config{DirectoryURL: ts.URL}

	if err := p.checkProfileAdvertised(context.Background(), cfg, "shortlived"); err != nil {
		t.Errorf("an advertised profile must be accepted: %v", err)
	}
	err := p.checkProfileAdvertised(context.Background(), cfg, "made-up")
	if err == nil {
		t.Fatal("an unadvertised profile must be refused")
	}
	if !strings.Contains(err.Error(), "default") || !strings.Contains(err.Error(), "shortlived") {
		t.Errorf("the refusal should name what is actually offered, got: %v", err)
	}
}

// TestCheckProfileAdvertisedPassesThroughWhenTheCAHasNoConcept. A CA that
// never implemented the draft cannot be judged against it, and refusing every
// profile name unconditionally would make this gateway less capable than the
// CA it is talking to.
func TestCheckProfileAdvertisedPassesThroughWhenTheCAHasNoConcept(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"newOrder": "https://ca.example/order"}`))
	}))
	defer ts.Close()
	p := &Provider{httpClient: ts.Client()}
	cfg := &Config{DirectoryURL: ts.URL}

	if err := p.checkProfileAdvertised(context.Background(), cfg, "anything"); err != nil {
		t.Errorf("a CA with no profiles concept must not refuse a name it cannot judge: %v", err)
	}
}

func decodeB64(t *testing.T, s string, v any) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("not base64url: %v", err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
}
