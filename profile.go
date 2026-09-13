package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

// This file exists because golang.org/x/crypto/acme — the library the rest of
// this gateway is built on — has no support for draft-ietf-acme-profiles as of
// v0.57.0, the latest release at the time this was written. There is no
// OrderOption for it and no field on Directory or Order to read one back.
//
// The alternative to what is here was silence: accept ca_profile, never send
// it, and let the certificate come back under whichever profile the CA
// defaults to. That is the exact failure this whole line of work exists to
// remove — a setting that is accepted and does nothing.
//
// So this hand-signs exactly one request the library cannot make: the
// profiled newOrder. Everything else — discovery, account registration,
// authorization, challenge solving, certificate download — still goes through
// the typed client unchanged, and the profile-less path (the overwhelming
// majority of requests) never runs a line of this file.
//
// Verified against a real implementation of the draft, not merely against the
// RFC 8555 text: github.com/letsencrypt/pebble/v2, which implements
// meta.profiles and the profile field on newOrder. A certificate requested
// under Pebble's "shortlived" profile came back valid for exactly the
// configured 518400 seconds; the same request under "default" came back valid
// for exactly 7776000. The commit message for the change that added this file
// has the full transcript.

// directoryMeta is the subset of RFC 8555 §7.1.1's directory object this
// gateway reads beyond what the typed client already exposes. golang.org/x/
// crypto/acme's Directory struct has no field for meta.profiles, so getting at
// it means a second, unauthenticated fetch of the same URL.
type directoryMeta struct {
	Meta struct {
		// Profiles maps a profile name to a human-readable description, per
		// draft-ietf-acme-profiles. Both keys and values are the CA's own
		// words; neither is interpreted here.
		Profiles map[string]string `json:"profiles"`
	} `json:"meta"`
	NewNonce string `json:"newNonce"`
	NewOrder string `json:"newOrder"`
}

// fetchDirectoryMeta reads the profiles a CA advertises.
//
// Unauthenticated: RFC 8555 directory objects carry no secret, and reading one
// needs no account. Returning an empty, non-nil map is the correct answer for
// a CA that does not implement the draft — the caller then treats every
// profile as unadvertised, which is the safe default: refuse rather than guess.
func fetchDirectoryMeta(ctx context.Context, hc *http.Client, directoryURL string) (*directoryMeta, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, directoryURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach the ACME directory at %s: %w", directoryURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("the ACME directory at %s answered %d: %s", directoryURL, resp.StatusCode, string(body))
	}
	var meta directoryMeta
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("the ACME directory at %s did not return valid JSON: %w", directoryURL, err)
	}
	if meta.Meta.Profiles == nil {
		meta.Meta.Profiles = map[string]string{}
	}
	return &meta, nil
}

// accountKID resolves the "kid" a signed request must carry: the account's own
// URL, per RFC 8555 §6.2 ("kid" field). Looked up rather than cached, because
// it is needed only on the profile path, which is rare enough that a lookup
// costs nothing worth avoiding and a stale cache would cost a debugging
// session nobody should have to have.
//
// client.Register has already run by the time this is called, so the account
// is guaranteed to exist; GetReg is the RFC 8555 way to ask "what is my own
// URL" without registering again.
func accountKID(ctx context.Context, client *acme.Client) (string, error) {
	acct, err := client.GetReg(ctx, "")
	if err != nil {
		return "", fmt.Errorf("could not resolve this ACME account's own URL: %w", err)
	}
	if acct.URI == "" {
		return "", fmt.Errorf("the CA answered the account lookup with no URL")
	}
	return acct.URI, nil
}

// wireIdentifier is one identifier in a newOrder request, RFC 8555 §7.1.3.
type wireIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// wireOrder is the subset of an order object this file reads directly, using
// the CA's own JSON field names rather than golang.org/x/crypto/acme's
// exported struct — that struct is populated by the library's own unexported
// decoder, which this file does not have access to and does not try to reuse.
type wireOrder struct {
	Status         string   `json:"status"`
	Authorizations []string `json:"authorizations"`
	Finalize       string   `json:"finalize"`
	Certificate    string   `json:"certificate"`
}

// createOrderWithProfile signs and sends a newOrder request naming a CA
// profile, and returns an *acme.Order built from the answer so every caller
// downstream — solveAuthorizations, WaitOrder, the rest of obtainCertificate —
// takes the same type it would have from the unmodified path and does not know
// this file exists.
func createOrderWithProfile(
	ctx context.Context, hc *http.Client, key crypto.Signer, kid, nonceURL, orderURL string,
	domains []string, profile string,
) (*acme.Order, error) {
	identifiers := make([]wireIdentifier, len(domains))
	for i, d := range domains {
		identifiers[i] = wireIdentifier{Type: "dns", Value: d}
	}
	payload := struct {
		Identifiers []wireIdentifier `json:"identifiers"`
		Profile     string           `json:"profile,omitempty"`
	}{Identifiers: identifiers, Profile: profile}

	res, err := signedPostWithRetry(ctx, hc, key, kid, nonceURL, orderURL, payload)
	if err != nil {
		return nil, fmt.Errorf("newOrder with profile %q: %w", profile, err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return nil, fmt.Errorf("the CA refused an order under profile %q (%d): %s", profile, res.StatusCode, string(body))
	}

	var wo wireOrder
	if err := json.NewDecoder(res.Body).Decode(&wo); err != nil {
		return nil, fmt.Errorf("the CA's order response was not valid JSON: %w", err)
	}
	return &acme.Order{
		URI:         res.Header.Get("Location"),
		Status:      wo.Status,
		AuthzURLs:   wo.Authorizations,
		FinalizeURL: wo.Finalize,
		CertURL:     wo.Certificate,
	}, nil
}

// finalizeOrder submits the CSR and polls the order's own URI to valid.
//
// Used for every finalize this gateway does, profiled or not — despite the
// name of the file it lives in, nothing here is specific to a profile. It
// replaced golang.org/x/crypto/acme's own CreateOrderCert, which does this by
// reading the Location header off the finalize response and polling that.
// RFC 8555 §7.4 does not require a CA to repeat Location there — the client
// already knows the order's URL — and Pebble, a real implementation, does
// not. CreateOrderCert then polls an empty URL and fails with "unsupported
// protocol scheme \"\"", a message that names none of this.
//
// Found the way most things in this codebase are found: by running it against
// something real rather than reading the RFC. It cost nothing to fix here too
// once the profiled path already needed its own finalize-and-poll — polling
// the URI the order was created at, which this function already has, works
// regardless of which behaviour the CA chose.
func finalizeOrder(
	ctx context.Context, client *acme.Client, hc *http.Client, key crypto.Signer, kid, nonceURL string,
	orderURI, finalizeURL string, csrDER []byte,
) (*acme.Order, error) {
	payload := struct {
		CSR string `json:"csr"`
	}{CSR: base64.RawURLEncoding.EncodeToString(csrDER)}

	res, err := signedPostWithRetry(ctx, hc, key, kid, nonceURL, finalizeURL, payload)
	if err != nil {
		return nil, fmt.Errorf("finalize: %w", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the CA answered finalize with %d", res.StatusCode)
	}

	for {
		// orderURI, not whatever the finalize response's Location header said
		// (or, on at least one real implementation, did not say) — see the
		// comment on the caller's copy of this URL in order.go.
		final, err := client.GetOrder(ctx, orderURI)
		if err != nil {
			return nil, fmt.Errorf("polling the order after finalize: %w", err)
		}
		switch final.Status {
		case acme.StatusValid:
			return final, nil
		case acme.StatusInvalid:
			return nil, &acme.OrderError{OrderURL: final.URI, Status: final.Status, Problem: final.Error}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// signedPostWithRetry signs and posts one JWS request, retrying exactly once
// on a stale nonce.
//
// badNonce is not a failure of the request; it is the server saying the nonce
// it handed out has already been spent or expired, and it hands back a fresh
// one in the same response for exactly this purpose (RFC 8555 §6.5). A CA is
// free to reject a nonce it considers old even when nothing else about the
// request is wrong — Pebble's test configuration does so on about one request
// in twenty deliberately, which is what this retry was tested against.
func signedPostWithRetry(
	ctx context.Context, hc *http.Client, key crypto.Signer, kid, nonceURL, url string, payload any,
) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		nonce, err := fetchNonce(ctx, hc, nonceURL)
		if err != nil {
			return nil, err
		}
		body, err := jwsSign(key, kid, nonce, url, payload)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/jose+json")

		res, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		if res.StatusCode == http.StatusBadRequest && attempt == 0 && isBadNonce(res) {
			res.Body.Close()
			continue
		}
		return res, nil
	}
}

// isBadNonce reads the problem type, then restores the body so the caller can
// still read it — the ordinary error path further up wants the raw problem
// document too, and a body consumed here would leave it empty there.
func isBadNonce(res *http.Response) bool {
	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "application/problem+json") {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 4096))
	res.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return false
	}
	var problem struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(body, &problem) != nil {
		return false
	}
	return strings.HasSuffix(problem.Type, ":badNonce")
}

// fetchNonce gets a fresh anti-replay nonce, per RFC 8555 §7.2.
func fetchNonce(ctx context.Context, hc *http.Client, nonceURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, nonceURL, nil)
	if err != nil {
		return "", err
	}
	res, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not get a nonce from %s: %w", nonceURL, err)
	}
	defer res.Body.Close()
	nonce := res.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", fmt.Errorf("%s answered with no Replay-Nonce header", nonceURL)
	}
	return nonce, nil
}

// jwsSign builds an RFC 7515 JWS in flattened form with the protected header
// required by RFC 8555 §6.2: alg, kid, nonce, url. No jwk form — every use in
// this file signs on behalf of an account that already exists, so kid is
// always the right choice and jwk (the form used only for the very first
// newAccount request) never arises here.
//
// ES256 and RS256 are the two algorithms this gateway's account keys can be:
// accountStore generates P-256 ECDSA by default and accepts an operator-
// supplied PEM of either kind. Anything else is refused rather than silently
// mis-signed.
func jwsSign(key crypto.Signer, kid, nonce, url string, payload any) ([]byte, error) {
	alg, hash, err := jwsAlgorithm(key)
	if err != nil {
		return nil, err
	}

	protectedJSON, err := json.Marshal(map[string]string{
		"alg": alg, "kid": kid, "nonce": nonce, "url": url,
	})
	if err != nil {
		return nil, err
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	protectedB64 := base64.RawURLEncoding.EncodeToString(protectedJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	sum := sha256.Sum256([]byte(protectedB64 + "." + payloadB64))
	sig, err := key.Sign(rand.Reader, sum[:], hash)
	if err != nil {
		return nil, fmt.Errorf("could not sign the request: %w", err)
	}
	sig, err = jwsEncodeSignature(key, sig)
	if err != nil {
		return nil, err
	}

	return json.Marshal(map[string]string{
		"protected": protectedB64,
		"payload":   payloadB64,
		"signature": base64.RawURLEncoding.EncodeToString(sig),
	})
}

// jwsAlgorithm names the JWS algorithm for this key's type. crypto.SHA256 in
// every case: RFC 7518 pairs ES256 with SHA-256 and this gateway does not
// generate P-384/P-521 account keys, so ES384/ES512 do not arise from its own
// key generation — only from an operator-supplied PEM, which this refuses
// rather than mis-labelling as ES256.
func jwsAlgorithm(key crypto.Signer) (alg string, hash crypto.Hash, err error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		if k.Curve.Params().BitSize != 256 {
			return "", 0, fmt.Errorf(
				"account key is ECDSA on a %d-bit curve; only P-256 (ES256) is supported for a profiled order",
				k.Curve.Params().BitSize)
		}
		return "ES256", crypto.SHA256, nil
	case *rsa.PrivateKey:
		return "RS256", crypto.SHA256, nil
	default:
		return "", 0, fmt.Errorf("account key type %T cannot sign a profiled order", key)
	}
}

// jwsEncodeSignature converts crypto.Signer's output into the form RFC 7518
// requires for the algorithm.
//
// RSA: PKCS#1 v1.5 signing already produces exactly the bytes RS256 wants; no
// conversion needed.
//
// ECDSA: crypto.Signer.Sign returns an ASN.1 DER-encoded SEQUENCE{r, s} — the
// signature format X.509 uses. RFC 7518 §3.4 requires the concatenation of r
// and s, each fixed-width at the curve's byte length, with no ASN.1 framing.
// A JWS carrying the DER bytes verifies against nothing: every conformant
// verifier expects the fixed-width form. This is the single most common way to
// build a JOSE library that works against your own tests and nothing else.
func jwsEncodeSignature(key crypto.Signer, sig []byte) ([]byte, error) {
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return sig, nil
	}
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &parsed); err != nil {
		return nil, fmt.Errorf("ECDSA signature was not the expected ASN.1 SEQUENCE{r,s}: %w", err)
	}
	size := (ecKey.Curve.Params().BitSize + 7) / 8
	raw := make([]byte, 2*size)
	parsed.R.FillBytes(raw[:size])
	parsed.S.FillBytes(raw[size:])
	return raw, nil
}

// createProfiledOrder is the Provider-level entry point profile.go's raw
// primitives above exist to serve: resolve this account's directory
// endpoints and kid, then create an order naming the profile.
func (p *Provider) createProfiledOrder(
	ctx context.Context, client *acme.Client, cfg *Config, domains []string, profile string,
) (*acme.Order, error) {
	dir, err := client.Discover(ctx)
	if err != nil {
		return nil, err
	}
	kid, err := accountKID(ctx, client)
	if err != nil {
		return nil, err
	}
	return createOrderWithProfile(ctx, p.httpClient, client.Key, kid, dir.NonceURL, dir.OrderURL, domains, profile)
}

// finalizeProfiledOrder is the Provider-level counterpart, returning the same
// shape client.CreateOrderCert would have: a certificate chain and its URL.
// finalizeOrderAndFetch is the Provider-level counterpart, returning the same
// shape client.CreateOrderCert would have: a certificate chain and its URL.
// The kid lookup costs one extra round trip per issuance — see the note on
// accountKID — which was an acceptable price only on the rare profile path
// before this replaced CreateOrderCert everywhere. It is not free, and the
// commit message for the change that made this unconditional says why paying
// it on every issuance was the right trade against a failure mode this had no
// other way to know about in advance.
func (p *Provider) finalizeOrderAndFetch(
	ctx context.Context, client *acme.Client, orderURI, finalizeURL string, csrDER []byte,
) ([][]byte, string, error) {
	dir, err := client.Discover(ctx)
	if err != nil {
		return nil, "", err
	}
	kid, err := accountKID(ctx, client)
	if err != nil {
		return nil, "", err
	}
	final, err := finalizeOrder(ctx, client, p.httpClient, client.Key, kid, dir.NonceURL, orderURI, finalizeURL, csrDER)
	if err != nil {
		return nil, "", err
	}
	der, err := client.FetchCert(ctx, final.CertURL, true)
	if err != nil {
		return nil, "", err
	}
	return der, final.CertURL, nil
}
