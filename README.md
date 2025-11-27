## Portal-tunnel

portal-tunnel is a tunneling tool that connects a locally running service to a relay server, allowing external access.

1. **Run with a config file** (Check the [example](cmd/config.yaml.example) for configuration details)

```bash
bin/portal-tunnel expose --config config.yaml
```

2. **Expose a single service directly**

```bash
bin/portal-tunnel expose --relay <url> [--relay <url> ...] --host localhost --port 8080 --name <service> \
  --description "Service description" \
  --tags tag1,tag2 \
  --thumbnail https://example.com/thumb.png \
  --owner owner-name \
  --hide
```
