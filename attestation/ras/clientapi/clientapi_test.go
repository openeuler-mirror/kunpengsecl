package clientapi

import (
	"context"
	"testing"
	"time"

	grpc "google.golang.org/grpc"
)

func TestClientAPI(t *testing.T) {
	const addr string = "127.0.0.1:40001"
	go StartServer(addr)

	conn, err := grpc.Dial(addr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		t.Errorf("Client: fail to connect %v", err)
	}
	defer conn.Close()
	c := NewRasClient(conn)
	t.Logf("Client: connect to %s", addr)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err = c.CreateIKCert(ctx, &CreateIKCertRequest{})
	if err != nil {
		t.Errorf("Client: invoke CreateIKCert error %v", err)
	}
	t.Logf("Client: invoke CreateIKCert ok")

	r, err := c.RegisterClient(ctx, &RegisterClientRequest{})
	if err != nil {
		t.Errorf("Client: invoke RegisterClient error %v", err)
	}
	t.Logf("Client: invoke RegisterClient ok, clientID=%d", r.GetClientId())

	_, err = c.SendHeartbeat(ctx, &SendHeartbeatRequest{ClientId: 1})
	if err != nil {
		t.Errorf("Client: invoke SendHeartbeat error %v", err)
	}
	t.Logf("Client: invoke SendHeartbeat ok")

	_, err = c.SendReport(ctx, &SendReportRequest{ClientId: 1})
	if err != nil {
		t.Errorf("Client: invoke SendReport error %v", err)
	}
	t.Logf("Client: invoke SendReport ok")

	u, err := c.UnregisterClient(ctx,
		&UnregisterClientRequest{ClientId: 1})
	if err != nil {
		t.Errorf("Client: invoke UnregisterClient error %v", err)
	}
	t.Logf("Client: invoke UnregisterClient %v", u.Result)

}
