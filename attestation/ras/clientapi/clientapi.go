package clientapi

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"
)

const (
	port = "127.0.0.1:40001"
)

type server struct {
	UnimplementedRasServer
}

func (s *server) CreateIKCert(ctx context.Context, in *CreateIKCertRequest) (*CreateIKCertReply, error) {
	log.Printf("Received: %v", "CreateIKCert")
	return &CreateIKCertReply{}, nil
}

func (s *server) RegisterClient(ctx context.Context, in *RegisterClientRequest) (*RegisterClientReply, error) {
	log.Printf("Received: %v", "RegisterClient")
	return &RegisterClientReply{}, nil
}

func (s *server) UnregisterClient(ctx context.Context, in *UnregisterClientRequest) (*UnregisterClientReply, error) {
	log.Printf("Received: %v", "UnregisterClient")
	return &UnregisterClientReply{}, nil
}

func (s *server) SendHeartbeat(ctx context.Context, in *SendHeartbeatRequest) (*SendHeartbeatReply, error) {
	log.Printf("Received: %v", "SendHeartbeat")
	return &SendHeartbeatReply{}, nil
}

func (s *server) SendReport(ctx context.Context, in *SendReportRequest) (*SendReportReply, error) {
	log.Printf("Received: %v", "SendReport")
	return &SendReportReply{}, nil
}

func startServer() {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterRasServer(s, &server{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func startClient() {
	conn, err := grpc.Dial(port, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := NewRasClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err = c.CreateIKCert(ctx, &CreateIKCertRequest{})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	log.Printf("CreateIKCert ok")

	_, err = c.RegisterClient(ctx, &RegisterClientRequest{})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	log.Printf("RegisterClient ok")

	_, err = c.UnregisterClient(ctx, &UnregisterClientRequest{})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	log.Printf("UnregisterClient ok")

	_, err = c.SendHeartbeat(ctx, &SendHeartbeatRequest{})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	log.Printf("SendHeartbeat ok")

	_, err = c.SendReport(ctx, &SendReportRequest{})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	log.Printf("SendReport ok")
}

func Test() {
	fmt.Println("hello, this is clientapi!")
	fmt.Println("start ras server!")
	go startServer()

	fmt.Println("start ras client!")
	startClient()
}
