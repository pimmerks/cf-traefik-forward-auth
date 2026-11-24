# cf-traefik-forward-auth

A small [Traefik ForwardAuth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/)
server that only lets a request through when it carries a valid
[Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/)
JWT.

Cloudflare Access adds a signed application token to every request it proxies to
your origin. If your origin is reachable in any way that bypasses Cloudflare,
those requests arrive without a valid token. This server makes Traefik reject
them.

## How it works

For every request, Traefik calls this server with the original request headers.
The server:

1. Reads the token from the `Cf-Access-Jwt-Assertion` header, falling back to
   the `CF_Authorization` cookie.
2. Verifies the RS256 signature against your team's public keys
   (`https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`). Keys are cached
   and refetched when Cloudflare rotates them.
3. Checks the issuer, expiry and not-before time, and that the token's audience
   matches one of the configured application AUD tags.

A valid token gets `200 OK`, and Traefik forwards the request. Anything else
gets `401 Unauthorized`, which Traefik returns to the client. If the keys cannot
be fetched, requests are rejected.

## Configuration

| Variable                | Required | Default | Description                                                                                                |
| ----------------------- | -------- | ------- | ---------------------------------------------------------------------------------------------------------- |
| `CF_ACCESS_TEAM_DOMAIN` | yes      |         | Your Zero Trust team name or domain: `myteam`, `myteam.cloudflareaccess.com` or the full `https://` URL.   |
| `CF_ACCESS_AUD`         | yes      |         | Application Audience (AUD) tag from the Access application's settings. Comma-separated for several apps.   |
| `LISTEN_ADDR`           | no       | `:8080` | Address to listen on.                                                                                      |
| `METRICS_ADDR`          | no       | `:9090` | Address of the Prometheus metrics listener, or `off` to disable it. See [Metrics](#metrics).               |
| `LOG_LEVEL`             | no       | `info`  | `debug`, `info`, `warn` or `error`. Denied requests log at `warn`, allowed requests at `debug`.            |
| `AUDIT_LOG`             | no       | `false` | `true` writes an audit entry for every request. See [Audit log](#audit-log).                               |

With several AUD tags, a token for any of the listed applications is accepted
on every route that uses the middleware. Run one instance per application if
you need them kept apart.

## Audit log

With `AUDIT_LOG=true`, every auth request writes one JSON line to stdout,
marked `"name": "audit"`:

- **Allowed** requests log at `INFO` with the user ID (`user_id`, the token's
  `sub`), `email`, `common_name` (service tokens), the original `url`, `method`
  and `client` address.
- **Denied** requests log at `WARN` with the `reason`, `url`, `method` and
  `client` address.

```json
{"time":"...","level":"INFO","msg":"access granted","name":"audit","method":"GET","url":"https://app.example.com/reports","client":"203.0.113.7","user_id":"7335d417-...","email":"user@example.com","common_name":""}
{"time":"...","level":"WARN","msg":"access denied","name":"audit","method":"GET","url":"https://app.example.com/reports","client":"203.0.113.7","reason":"no Cloudflare Access token in request"}
```

Audit entries go through the same logger as everything else, so `LOG_LEVEL`
applies: at `warn` or `error` the `INFO` entries for allowed requests are not
written. The URL, method and client address come from the `X-Forwarded-*`
headers Traefik sends.

## Metrics

Prometheus metrics are served at `/metrics` on a separate port, `:9090` by
default, so they are not reachable through the auth port that Traefik calls.
Do not publish that port outside the network your Prometheus scrapes from.

| Metric                                      | Labels             | Description                                                           |
| ------------------------------------------- | ------------------ | --------------------------------------------------------------------- |
| `cf_forward_auth_requests_total`            | `result`, `reason` | Auth requests. `result` is `granted` or `denied`; see reasons below.  |
| `cf_forward_auth_request_duration_seconds`  | `result`           | Histogram of the time taken to answer, including any key fetch.       |
| `cf_forward_auth_key_fetches_total`         | `code`             | Fetches of the signing keys, by HTTP status or `error` for no response. |

Denied requests carry one of these `reason` values: `no_token`, `bad_audience`,
`expired` or `invalid` (bad signature, wrong issuer, malformed token, and
anything else). Granted requests have an empty `reason`. The standard Go
runtime (`go_*`) and process (`process_*`) metrics are included too.

A rise in `cf_forward_auth_key_fetches_total{code!="200"}` means Cloudflare's
certs endpoint is unreachable, which shows up to users as every request being
denied.

## Endpoints

| Path       | Description                                                |
| ---------- | ---------------------------------------------------------- |
| `/healthz` | Liveness check, returns `204`.                             |
| any other  | The auth check. Point the ForwardAuth `address` here.      |

`/metrics` is on the metrics port, not this one.

On success the response carries these headers, which Traefik can pass on to
your backend via `authResponseHeaders`:

| Header               | Value                                              |
| -------------------- | -------------------------------------------------- |
| `X-Auth-Email`       | The user's email address (user logins).            |
| `X-Auth-User`        | The user's Access ID, the token's `sub` (user logins). |
| `X-Auth-Common-Name` | The service token's client ID (service tokens).    |

Traefik removes any header listed in `authResponseHeaders` that the auth
response does not set, so clients cannot spoof these.

## Example with Docker Compose

[`compose.yaml`](compose.yaml) runs Traefik with this server as a ForwardAuth
middleware in front of a demo `whoami` service. Create a `.env` file next to it:

```bash
CF_ACCESS_TEAM_DOMAIN=myteam
CF_ACCESS_AUD=<aud-tag>
APP_HOST=app.example.com
```

Then start it:

```bash
docker compose up
```

The part that matters for your own setup is the middleware definition on the
`cf-auth` service and the `middlewares=cf-access` label on each router you want
protected.

## Container image

Pushing a version tag such as `v1.2.3` (or publishing a GitHub release that
creates one) builds a `linux/amd64` and `linux/arm64` image and pushes it to
`ghcr.io/pimmerks/cf-traefik-forward-auth`, tagged `1.2.3`, `1.2` and `latest`.

## Development

```bash
go test ./...
```

```bash
CF_ACCESS_TEAM_DOMAIN=myteam CF_ACCESS_AUD=<aud-tag> go run .
```
