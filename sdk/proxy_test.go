package sdk

import (
	"bufio"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProxyConnectionAnswers503WhenOriginIsDown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedOrigin := listener.Addr().String()
	require.NoError(t, listener.Close())

	visitor, relay := net.Pipe()
	defer visitor.Close()
	proxied := make(chan error, 1)
	go func() { proxied <- proxyConnection(t.Context(), closedOrigin, relay) }()

	response, err := http.ReadResponse(bufio.NewReader(visitor), nil)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, response.StatusCode)
	require.NoError(t, <-proxied)
}
