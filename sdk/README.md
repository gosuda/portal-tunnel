# Portal Go SDK

The SDK exposes one service through a dynamic relay pool. `Exposure` implements
`net.Listener`; relay failures are isolated and observable through `Relays`,
`Updates`, and `WaitReady`.

```go
identity, err := sdk.GenerateIdentity("my-service")
if err != nil {
	return err
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

Applications own identity persistence with `ParseIdentity` and
`MarshalIdentity`. Local targets are separate from relay configuration:

```go
return sdk.ProxyWithConfig(ctx, exposure, sdk.ProxyConfig{
	TCPTarget: "127.0.0.1:3000",
	UDPTarget: "127.0.0.1:5353",
})
```

`Proxy`, `ProxyUDP`, and `ProxyWithConfig` close the exposure when proxying
stops. Do not consume `Accept` or `AcceptDatagram` concurrently with the
corresponding proxy helper.
