package transport

import (
	"net"

	"github.com/quic-go/quic-go"

	"github.com/gosuda/portal-tunnel/v2/types"
)

type ClientDatagram struct {
	session *datagramSession
}

func NewClientDatagram(onReceiveError func(error)) *ClientDatagram {
	return &ClientDatagram{
		session: newDatagramSession(256, false, onReceiveError),
	}
}

func (d *ClientDatagram) BindBackhaul(conn *quic.Conn) (<-chan struct{}, error) {
	if d == nil || d.session == nil {
		if conn != nil {
			_ = conn.CloseWithError(0, "listener closed")
		}
		return nil, net.ErrClosed
	}
	return d.session.Bind(conn)
}

func (d *ClientDatagram) Accept(done <-chan struct{}) (types.DatagramFrame, error) {
	if d == nil || d.session == nil {
		return types.DatagramFrame{}, net.ErrClosed
	}

	select {
	case <-done:
		return types.DatagramFrame{}, net.ErrClosed
	case dg := <-d.session.incoming:
		return dg, nil
	}
}

func (d *ClientDatagram) Send(flowID uint32, payload []byte) error {
	if d == nil || d.session == nil {
		return net.ErrClosed
	}
	return d.session.Send(flowID, payload)
}

func (d *ClientDatagram) Connected() bool {
	return d != nil && d.session != nil && d.session.hasConnection()
}

func (d *ClientDatagram) Clear(reason string) {
	if d == nil || d.session == nil {
		return
	}
	d.session.Clear(reason)
}

func (d *ClientDatagram) Close() {
	if d == nil || d.session == nil {
		return
	}
	d.session.Stop("listener closed")
}
