# Portal Go SDK

The SDK exposes one service through a dynamic relay pool. `Exposure` implements
`net.Listener`; relay failures are isolated and observable through `Relays`,
`Updates`, and `WaitReady`.

```go
identity := types.Identity{
	Name:       "my-service",
	Address:    "0x...", // derived from PrivateKey by the identity owner
	PublicKey:  "...",   // compressed secp256k1 public key
	PrivateKey: "...",   // keep secret; load it from your application's store
}
exposure, err := sdk.Expose(ctx, sdk.ExposeConfig{
	RelayURLs: []string{"https://relay.example"},
	Identity:  identity,
})
if err != nil {
	return err
}
defer exposure.Close()

ready, err := exposure.WaitReady(ctx)
if err != nil {
	return err
}
for _, relay := range ready {
	log.Printf("ready: %s", relay.PublicURL)
}

server := &http.Server{Handler: handler}
return server.Serve(exposure)
```

`Updates` is a best-effort notification stream for one consumer. Use `Relays`
for the authoritative, sorted point-in-time snapshot.

The SDK owns relay/lease lifecycle only. Pass a `types.Identity` to `Expose`;
identity files are loaded and persisted by the CLI or agent, which own that
storage policy. Local targets are separate from relay configuration:

```go
return sdk.ProxyWithConfig(ctx, exposure, sdk.ProxyConfig{
	TCPTarget: "127.0.0.1:3000",
	UDPTarget: "127.0.0.1:5353",
})
```

`Proxy`, `ProxyUDP`, and `ProxyWithConfig` close the exposure when proxying
stops. Do not consume `Accept` or `AcceptDatagram` concurrently with the
corresponding proxy helper.
