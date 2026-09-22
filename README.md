# certpilot-gateway-acme

A [CertPilot](https://github.com/certpilot/certpilot) gateway for any RFC 8555
ACME certificate authority — Let's Encrypt, ZeroSSL, Buypass, Google Trust
Services, or an internal one.

Implements [`provider.v1`](https://github.com/certpilot/certpilot-gateway-sdk).

```
docker run --rm -p 9092:9092 ghcr.io/certpilot/gateway-acme:0.3.0
```

Then register it, from the core:

```
POST /api/v1/ca-accounts   { "gateway_addr": "gateway-acme:9092", ... }
```

## What it does

| | |
|:---|:---|
| Challenges | `dns-01` (Cloudflare, or any webhook), `http-01` |
| Wildcards | yes, over `dns-01` only — ACME permits no other |
| Key types | RSA, ECDSA |
| Revocation | yes |
| ARI | RFC 9773 renewal windows, honoured and reported upward |

**ARI is the part worth knowing about.** A CA that publishes renewal information
is telling you when *it* wants the certificate replaced, and honouring that is
what lets a CA drain a mass-revocation event gradually instead of every client
renewing at once. This gateway reports the window; the core picks a time inside
it rather than renewing at the start.

## Credentials

**This gateway holds no credential of its own.** Each CA account carries the
ACME account key and the DNS provider token it issues under, and they arrive in
`provider_config` on every call. The process is authorised to sign nothing —
which is the point, because a gateway that could issue on its own is a gateway
worth stealing.

## Flags

```
-port              9092
-directory         letsencrypt-staging | letsencrypt | zerossl | buypass | google | <url>
-insecure          serve without TLS. Loopback only
-tls-cert/-tls-key/-tls-ca
```

The core-to-gateway channel carries CSRs, private keys and CA credentials, so it
is mutually authenticated by default. `-insecure` exists for local work and
warns loudly.

`-directory` defaults to **Let's Encrypt staging**, deliberately: the production
endpoint has rate limits that punish a misconfiguration for a week, and staging
is where you find out. A CA account may name its own directory and overrides
this.

## Limitations

- **No issuer inventory.** ACME publishes no endpoint listing a CA's issuer
  certificates — they arrive with each issuance. `GetCAInfo` answers with the
  CA's identity and the profiles the directory advertises, read live, but no
  issuers. ACME-signed certificates therefore do not populate CertPilot's CA
  hierarchy view the way Vault-signed ones do.
- **`DescribeProfile` is not implemented**, and answers `Unimplemented` — a
  supported answer under the v0.3.0 contract.
- **Wildcards need `dns-01`.** That is ACME's rule, not this gateway's.
- **External Account Binding is unverified against a real CA.** The binding is
  built and unit-tested; nothing in CI has ever contacted ZeroSSL, Google Trust
  Services or SSL.com. Marked 🧪 in CertPilot's
  [implementation status](https://github.com/certpilot/certpilot/blob/main/docs/status.md).
- **Issuance is not exercised in CI.** The conformance job runs the contract
  checks and reports its issuance checks as *skipped*, because a CA has to
  validate a domain CI does not control.

[The ACME gateway](https://github.com/certpilot/certpilot/blob/main/docs/gateways/acme.md)
is the operational guide: challenges, directories and rate limits, and where the
security boundary sits.

## Building

```
make build test
docker build -t gateway-acme .
```

## Conformance

```
go run github.com/certpilot/certpilot-gateway-sdk/cmd/conformance@latest -addr localhost:9092 -insecure
```

CI runs this on every pull request. It is what answers "does this still
implement the contract the core expects" now that the two live in different
repositories.

## Releases

`0.3.0`, on `linux/amd64` and `linux/arm64`. Images publish on a tag, never on a
merge, so `latest` means the most recent release rather than the most recent
commit — pin anyway for anything you depend on.

The Go module is tagged in step with the image, so
`go run github.com/certpilot/certpilot-gateway-acme/cmd@v0.3.0` runs the same code
the image contains.

## Licence

Apache 2.0.
