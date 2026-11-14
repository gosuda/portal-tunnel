# Optional relay observability

This Compose overlay adds Prometheus and Grafana to the relay in the repository
root. It follows the authenticated metrics route implemented in #708. The base
`docker-compose.yml` runs without this profile.

## Start metrics and dashboards

Set `ADMIN_TOKEN` in the root `.env` as described in the deployment guide, and
export the same value in the shell before starting Compose. The Prometheus
secret reads the exported value and is mounted for its `nobody` user only:

```sh
: "${ADMIN_TOKEN:?Export the relay ADMIN_TOKEN first}"
export GRAFANA_ADMIN_PASSWORD='choose-a-strong-password'
docker compose -f docker-compose.yml -f docs/examples/observability/compose.yml \
  --profile observability up -d
```

The secret requires `ADMIN_TOKEN` in the shell environment; a value present
only in `.env` is not enough. Compose also passes the exported value to the
relay, so both services use the same token.

Prometheus shares the relay's network namespace and scrapes
`https://localhost:443/api/admin/metrics` with that bearer token. The relay
requires the HTTP Host and TLS name to match; the default configuration uses
`localhost` for both. If `PORTAL_URL` uses another hostname, set the scrape
target and `tls_config.server_name` in `prometheus.yml` to its root hostname
and make that name resolve to the relay inside the container. For a production
certificate, also set `insecure_skip_verify: false` and configure the issuing
CA if the container does not already trust it.

Open Grafana at <http://localhost:3000>; its host port binds to loopback.
Prometheus is available to Grafana within the Compose network. In Grafana
Explore, check that `up{job="portal-relay"}` is `1`. The `Portal Relay`
dashboard uses the metrics emitted by the current relay: active leases, stream
connections, UDP flows, aggregate stream bytes, HTTP handler traffic and
latency, Go runtime, and process metrics. The HTTP panels include the relay
API and frontend, not forwarded tenant requests. Stream byte totals exclude
UDP payloads. The current stats API has no transport or application traffic
breakdown, so those panels from #654 are not included.
