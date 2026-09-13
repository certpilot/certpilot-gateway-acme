# certpilot-gateway-acme

A [CertPilot](https://github.com/certpilot/certpilot) gateway for any RFC 8555
ACME certificate authority — Let's Encrypt, ZeroSSL, Buypass, Google Trust
Services, or an internal one.

Implements [`provider.v1`](https://github.com/certpilot/certpilot-gateway-sdk).

```
docker run --rm -p 9092:9092 ghcr.io/certpilot/gateway-acme:latest
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

## Licence

Apache 2.0.
