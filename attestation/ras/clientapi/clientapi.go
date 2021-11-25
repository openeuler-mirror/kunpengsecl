/*
Copyright (c) Huawei Technologies Co., Ltd. 2021.
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of the Mulan PSL v2.
You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
PURPOSE.
See the Mulan PSL v2 for more details.

Author: wucaijun
Create: 2021-10-08
Description: Using grpc to implement the service API.
*/

package clientapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"log"
	"net"
	"sync"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/pca"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/cache"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"

	"google.golang.org/grpc"
)

const (
	constDEFAULTRAC     int           = 1000
	constDEFAULTTIMEOUT time.Duration = 100 * time.Second
)

type (
	clientInfo struct {
		cache cache.Cache
	}
)

type service struct {
	UnimplementedRasServer
	sync.Mutex
	cli map[int64]*clientInfo
}

func (s *service) CreateIKCert(ctx context.Context, in *CreateIKCertRequest) (*CreateIKCertReply, error) {
	to, err := pca.GetIkCert(in.EkCert, in.IkPub, in.IkName)
	if err != nil {
		return &CreateIKCertReply{}, errors.New("Failed to get ikCert")
	}
	return &CreateIKCertReply{
		IcEncrypted: &CertEncrypted{
			EncryptedIC: to.EncryptedCert,
			IV:          to.TPMSymKeyParams.IV,
		},
		Challenge: &Challenge{
			CredBlob:        to.TPMSymKeyParams.CredBlob,
			EncryptedSecret: to.TPMSymKeyParams.EncryptedSecret,
			EncryptAlg:      to.TPMSymKeyParams.EncryptAlg,
			EncryptParam:    to.TPMSymKeyParams.EncryptParam,
		},
	}, nil
}

// RegisterClient TODO: need a challenge and some statement for check nil pointer (this package functions all need this)
func (s *service) RegisterClient(ctx context.Context, in *RegisterClientRequest) (*RegisterClientReply, error) {
	log.Printf("Server: receive RegisterClient")
	// register and get clientId
	ci := in.GetClientInfo().GetClientInfo()
	cim := map[string]string{}
	err := json.Unmarshal([]byte(ci), &cim)
	if err != nil {
		return nil, err
	}
	eci := &entity.ClientInfo{
		Info: cim,
	}
	ic := in.GetIc().GetCert()
	clientID, err := trustmgr.RegisterClient(eci, ic)
	if err != nil {
		return nil, err
	}

	s.Lock()
	info, ok := s.cli[clientID]
	if !ok {
		info = &clientInfo{}
		s.cli[clientID] = info
		log.Printf("reg %d", clientID)
	}
	info.cache.ClearCommands()
	info.cache.UpdateHeartBeat()
	info.cache.GetTrustReport()
	s.Unlock()

	hd := config.GetDefault().GetHBDuration()
	td := config.GetDefault().GetTrustDuration()

	return &RegisterClientReply{
		ClientId: clientID,
		ClientConfig: &ClientConfig{
			HbDurationSeconds:    int64(hd.Seconds()),
			TrustDurationSeconds: int64(td.Seconds()),
		},
	}, nil
}

func (s *service) UnregisterClient(ctx context.Context, in *UnregisterClientRequest) (*UnregisterClientReply, error) {
	log.Printf("Server: receive UnregisterClient")
	cid := in.GetClientId()
	s.Lock()
	result := false
	_, ok := s.cli[cid]
	if ok {
		log.Printf("delete %d", cid)
		delete(s.cli, cid)
		trustmgr.UnRegisterClient(cid)
		result = true
	}
	defer s.Unlock()
	return &UnregisterClientReply{Result: result}, nil
}

func (s *service) SendHeartbeat(ctx context.Context, in *SendHeartbeatRequest) (*SendHeartbeatReply, error) {
	log.Printf("Server: receive SendHeartbeat")
	var nextAction uint64
	var nonce uint64
	cid := in.GetClientId()
	s.Lock()
	info, ok := s.cli[cid]
	if ok {
		var err error
		log.Printf("hb %d", cid)
		info.cache.UpdateHeartBeat()
		if info.cache.HasCommands() {
			nextAction = info.cache.GetCommands()
			nonce, err = info.cache.CreateNonce()
			if err != nil {
				return nil, err
			}
		}
	}
	s.Unlock()
	return &SendHeartbeatReply{
		NextAction: nextAction,
		ActionParameters: &ActionParameters{
			ClientConfig: &ClientConfig{},
			Nonce:        nonce,
		},
	}, nil
}

func (s *service) SendReport(ctx context.Context, in *SendReportRequest) (*SendReportReply, error) {
	log.Printf("Server: receive SendReport")
	cid := in.GetClientId()
	s.Lock()
	info, ok := s.cli[cid]
	if ok {
		report := in.GetTrustReport()
		// transform pcr info from struct in grpc to struct in ras
		opvs := report.GetPcrInfo().GetPcrValues()
		tpvs := map[int]string{}
		for k, v := range opvs {
			tpvs[int(k)] = v
		}
		// transfrom manifest from struct in grpc to struct in ras
		oms := report.GetManifest()
		var tms []entity.Manifest
		for _, om := range oms {
			handled := false
			var mi *entity.Manifest
			var err error

			switch strings.ToLower(om.Type) {
			case "bios":
				mi, err = unmarshalBIOSManifest(om.Item)
			case "ima":
				mi, err = unmarshalIMAManifest(om.Item)
			default:
				err = fmt.Errorf("unsupported manifest type: %s", om.Type)
			}
			if err != nil {
				return nil, err
			}

			// if type has existed
			for _, tm := range tms {
				if om.Type == tm.Type {
					handled = true
					tm.Items = append(tm.Items, mi.Items...)
					break
				}
			}
			if !handled {
				tms = append(tms, *mi)
			}
		}
		err := trustmgr.RecordReport(&entity.Report{
			PcrInfo: entity.PcrInfo{
				AlgName: report.GetPcrInfo().GetAlgorithm(),
				Values:  tpvs,
				Quote: entity.PcrQuote{
					Quoted: report.GetPcrInfo().GetPcrQuote().Quoted,
				},
			},
			Manifest: tms,
			ClientID: cid,
		})
		if err != nil {
			return nil, err
		}

		log.Printf("report %d", cid)
		info.cache.ClearCommands()
		info.cache.UpdateTrustReport()
	}
	s.Unlock()
	return &SendReportReply{Result: true}, nil
}

// StartServer starts ras server and provides rpc services.
func StartServer(addr string) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Server: fail to listen at %v", err)
		return
	}
	s := grpc.NewServer()
	svc := &service{}
	svc.cli = make(map[int64]*clientInfo, constDEFAULTRAC)
	RegisterRasServer(s, svc)
	log.Printf("Server: listen at %s", addr)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Server: fail to serve %v", err)
	}
}

type rasConn struct {
	ctx    context.Context
	cancel context.CancelFunc
	conn   *grpc.ClientConn
	c      RasClient
}

func makesock(addr string) (*rasConn, error) {
	ras := &rasConn{}
	conn, err := grpc.Dial(addr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return nil, errors.New("Client: fail to connect " + addr)
	}
	ras.conn = conn
	ras.c = NewRasClient(conn)
	ras.ctx, ras.cancel = context.WithTimeout(context.Background(), constDEFAULTTIMEOUT)
	log.Printf("Client: connect to %s", addr)
	return ras, nil
}

// DoCreateIKCert creates an identity certificate from ras server.
func DoCreateIKCert(addr string, in *CreateIKCertRequest) (*CreateIKCertReply, error) {
	ras, err := makesock(addr)
	if err != nil {
		log.Fatalf("%v", err)
		return nil, err
	}
	defer ras.conn.Close()
	defer ras.cancel()

	bk, err := ras.c.CreateIKCert(ras.ctx, in)
	if err != nil {
		log.Fatalf("Client: invoke CreateIKCert error %v", err)
		return nil, err
	}
	log.Printf("Client: invoke CreateIKCert ok")
	return bk, nil
}

// DoRegisterClient registers the rac to the ras server.
func DoRegisterClient(addr string, in *RegisterClientRequest) (*RegisterClientReply, error) {
	ras, err := makesock(addr)
	if err != nil {
		log.Fatalf("%v", err)
		return nil, err
	}
	defer ras.conn.Close()
	defer ras.cancel()

	bk, err := ras.c.RegisterClient(ras.ctx, in)
	if err != nil {
		log.Fatalf("Client: invoke RegisterClient error %v", err)
		return nil, err
	}
	log.Printf("Client: invoke RegisterClient ok, clientID=%d", bk.GetClientId())
	return bk, nil
}

// DoUnregisterClient unregisters the rac from the ras server.
func DoUnregisterClient(addr string, in *UnregisterClientRequest) (*UnregisterClientReply, error) {
	ras, err := makesock(addr)
	if err != nil {
		log.Fatalf("%v", err)
		return nil, err
	}
	defer ras.conn.Close()
	defer ras.cancel()

	bk, err := ras.c.UnregisterClient(ras.ctx, in)
	if err != nil {
		log.Fatalf("Client: invoke UnregisterClient error %v", err)
		return nil, err
	}
	log.Printf("Client: invoke UnregisterClient %v", bk.Result)
	return bk, nil
}

// DoSendHeartbeat sends a heart beat message to the ras server.
func DoSendHeartbeat(addr string, in *SendHeartbeatRequest) (*SendHeartbeatReply, error) {
	ras, err := makesock(addr)
	if err != nil {
		log.Fatalf("%v", err)
		return nil, err
	}
	defer ras.conn.Close()
	defer ras.cancel()

	bk, err := ras.c.SendHeartbeat(ras.ctx, in)
	if err != nil {
		log.Fatalf("Client: invoke SendHeartbeat error %v", err)
		return nil, err
	}
	log.Printf("Client: invoke SendHeartbeat ok")
	//bk.NextAction = 123
	return bk, nil
}

// DoSendReport sends a trust report message to the ras server.
func DoSendReport(addr string, in *SendReportRequest) (*SendReportReply, error) {
	ras, err := makesock(addr)
	if err != nil {
		log.Fatalf("%v", err)
		return nil, err
	}
	defer ras.conn.Close()
	defer ras.cancel()

	bk, err := ras.c.SendReport(ras.ctx, in)
	if err != nil {
		log.Fatalf("Client: invoke SendReport error %v", err)
		return nil, err
	}
	log.Printf("Client: invoke SendReport ok")
	return bk, nil
}

func unmarshalBIOSManifest(content []byte) (*entity.Manifest, error) {
	result := &entity.Manifest{
		Type: "bios",
	}
	str := string(content)
	rows := strings.Split(str, "\n")
	for i, row := range rows {
		items := strings.Split(row, " ")
		if len(items) == 3 {
			name := items[2] + "-" + fmt.Sprintf("%d", i)
			bmi := entity.BIOSManifestItem{
				Pcr:  items[0],
				Hash: items[1],
				Name: name,
			}
			detail, err := json.Marshal(bmi)
			if err != nil {
				return nil, err
			}
			result.Items = append(result.Items, entity.ManifestItem{
				Name:   name,
				Value:  items[1],
				Detail: string(detail),
			})
		} else {
			return nil, errors.New("bios manifest format is wrong")
		}
	}
	return result, nil
}

func unmarshalIMAManifest(content []byte) (*entity.Manifest, error) {
	result := &entity.Manifest{
		Type: "ima",
	}
	str := string(content)
	rows := strings.Split(str, "\n")
	for _, row := range rows {
		items := strings.Split(row, " ")
		if len(items) == 5 {
			imi := entity.IMAManifestItem{
				Pcr:          items[0],
				TemplateHash: items[1],
				TemplateName: items[2],
				FiledataHash: items[3],
				FilenameHint: items[4],
			}
			detail, err := json.Marshal(imi)
			if err != nil {
				return nil, err
			}
			result.Items = append(result.Items, entity.ManifestItem{
				Name:   items[4],
				Value:  items[1],
				Detail: string(detail),
			})
		} else {
			return nil, errors.New("ima manifest format is wrong")
		}
	}
	return result, nil
}
