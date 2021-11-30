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
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/pca"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/cache"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"

	"google.golang.org/grpc"
)

const (
	constDEFAULTTIMEOUT time.Duration = 100 * time.Second
)

type service struct {
	UnimplementedRasServer
	cm *cache.CacheMgr
}

func (s *service) CreateIKCert(ctx context.Context, in *CreateIKCertRequest) (*CreateIKCertReply, error) {
	to, err := pca.GetIkCert(in.EkCert, in.IkPub, in.IkName)
	if err != nil {
		return &CreateIKCertReply{}, errors.New("failed to get ikCert")
	}
	return &CreateIKCertReply{
		EncryptedIC:     to.EncryptedCert,
		CredBlob:        to.TPMSymKeyParams.CredBlob,
		EncryptedSecret: to.TPMSymKeyParams.EncryptedSecret,
		EncryptAlg:      to.TPMSymKeyParams.EncryptAlg,
		EncryptParam:    to.TPMSymKeyParams.EncryptParam,
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

	cfg := config.GetDefault(config.ConfServer)
	hd := cfg.GetHBDuration()
	td := cfg.GetTrustDuration()

	s.cm.Lock()
	defer s.cm.Unlock()

	c := s.cm.CreateCache(clientID)
	if c == nil {
		return nil, fmt.Errorf("client %d failed to create cache", clientID)
	}
	log.Printf("reg %d", clientID)

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
	result := false
	if cid <= 0 {
		return &UnregisterClientReply{Result: result}, fmt.Errorf("client id %v is illegal", cid)
	}

	s.cm.Lock()
	defer s.cm.Unlock()

	c := s.cm.GetCache(in.ClientId)
	if c != nil {
		log.Printf("delete %d", cid)
		s.cm.RemoveCache(cid)
		err := trustmgr.UnRegisterClient(cid)
		if err != nil {
			return &UnregisterClientReply{Result: result}, fmt.Errorf("unregister failed. err: %v", err)
		}
		result = true
	}
	return &UnregisterClientReply{Result: result}, nil
}

func (s *service) SendHeartbeat(ctx context.Context, in *SendHeartbeatRequest) (*SendHeartbeatReply, error) {
	log.Printf("Server: receive SendHeartbeat")
	var nextAction uint64
	var nonce uint64
	cid := in.GetClientId()

	s.cm.Lock()
	c := s.cm.GetCache(cid)
	s.cm.Unlock()

	if c != nil {
		var err error
		log.Printf("hb %d", cid)
		c.UpdateHeartBeat()
		if c.HasCommands() {
			nextAction = c.GetCommands()
			nonce, err = c.CreateNonce()
			if err != nil {
				return nil, err
			}
		}
	}

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

	s.cm.Lock()
	c := s.cm.GetCache(cid)
	s.cm.Unlock()

	if c == nil {
		return &SendReportReply{Result: false}, fmt.Errorf("unregisted client: %d", cid)
	}

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
			return &SendReportReply{Result: false}, err
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
		return &SendReportReply{Result: false}, err
	}

	log.Printf("report %d", cid)
	c.ClearCommands()
	c.UpdateTrustReport()

	return &SendReportReply{Result: true}, nil
}

func NewServer(cm *cache.CacheMgr) *service {
	return &service{cm: cm}
}

// StartServer starts ras server and provides rpc services.
func StartServer(addr string, cm *cache.CacheMgr) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Server: fail to listen at %v", err)
		return
	}
	s := grpc.NewServer()
	err = cm.Initialize()
	if err != nil {
		log.Fatalf("Server: initialize cache failed. err: %v", err)
		return
	}
	svc := NewServer(cm)
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
		log.Printf("%v", err)
		return nil, err
	}
	defer ras.conn.Close()
	defer ras.cancel()

	bk, err := ras.c.CreateIKCert(ras.ctx, in)
	if err != nil {
		log.Printf("Client: invoke CreateIKCert error %v", err)
		return nil, err
	}
	log.Printf("Client: invoke CreateIKCert ok")
	return bk, nil
}

// DoRegisterClient registers the rac to the ras server.
func DoRegisterClient(addr string, in *RegisterClientRequest) (*RegisterClientReply, error) {
	ras, err := makesock(addr)
	if err != nil {
		log.Printf("%v", err)
		return nil, err
	}
	defer ras.conn.Close()
	defer ras.cancel()

	bk, err := ras.c.RegisterClient(ras.ctx, in)
	if err != nil {
		log.Printf("Client: invoke RegisterClient error %v", err)
		return nil, err
	}
	log.Printf("Client: invoke RegisterClient ok, clientID=%d", bk.GetClientId())
	return bk, nil
}

// DoUnregisterClient unregisters the rac from the ras server.
func DoUnregisterClient(addr string, in *UnregisterClientRequest) (*UnregisterClientReply, error) {
	ras, err := makesock(addr)
	if err != nil {
		log.Printf("%v", err)
		return nil, err
	}
	defer ras.conn.Close()
	defer ras.cancel()

	bk, err := ras.c.UnregisterClient(ras.ctx, in)
	if err != nil {
		log.Printf("Client: invoke UnregisterClient error %v", err)
		return nil, err
	}
	log.Printf("Client: invoke UnregisterClient %v", bk.Result)
	return bk, nil
}

// DoSendHeartbeat sends a heart beat message to the ras server.
func DoSendHeartbeat(addr string, in *SendHeartbeatRequest) (*SendHeartbeatReply, error) {
	ras, err := makesock(addr)
	if err != nil {
		log.Printf("%v", err)
		return nil, err
	}
	defer ras.conn.Close()
	defer ras.cancel()

	bk, err := ras.c.SendHeartbeat(ras.ctx, in)
	if err != nil {
		log.Printf("Client: invoke SendHeartbeat error %v", err)
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
		log.Printf("%v", err)
		return nil, err
	}
	defer ras.conn.Close()
	defer ras.cancel()

	bk, err := ras.c.SendReport(ras.ctx, in)
	if err != nil {
		log.Printf("Client: invoke SendReport error %v", err)
		return nil, err
	}
	log.Printf("Client: invoke SendReport ok")
	return bk, nil
}

func unmarshalBIOSManifest(content []byte) (*entity.Manifest, error) {
	result := &entity.Manifest{
		Type:  "bios",
		Items: []entity.ManifestItem{},
	}
	var point int64 = 0

	_, err := readSHA1BIOSEventLog(content, &point)
	if err != nil {
		return nil, err
	}
	SpecID := getSpecID(content)
	// if SpecID is "Spec ID Event03", this is a event2 log bytes stream
	// TODO: getSpecID return "Spec ID Event03\x00", reason is unknown
	if strings.Contains(SpecID, EVENT2_SPEC_ID) {
		for {
			event2Log, err := readBIOSEvent2Log(content, &point)
			if err != nil {
				break
			}
			detail, err := json.Marshal(event2Log)
			if err != nil {
				break
			}
			result.Items = append(result.Items, entity.ManifestItem{
				Name:   fmt.Sprint(event2Log.BType),
				Value:  string(event2Log.Data),
				Detail: string(detail),
			})
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

const (
	SHA1_ALG_ID    = "0400"
	SHA256_ALG_ID  = "0b00"
	EVENT2_SPEC_ID = "Spec ID Event03"
)

func readSHA1BIOSEventLog(origin []byte, point *int64) (*entity.BIOSManifestItem, error) {
	const (
		PCR_LEN       int8 = 4
		BIOS_TYPE_LEN int8 = 4
		DIGEST_LEN    int8 = 20
		// DATA_LEN_LEN is bytes length of bios manifest item value bytes length
		DATA_LEN_LEN int8 = 4
	)

	pcrBytes := make([]byte, PCR_LEN)
	bTypeBytes := make([]byte, BIOS_TYPE_LEN)
	digestBytes := make([]byte, DIGEST_LEN)
	dataLengthBytes := make([]byte, DATA_LEN_LEN)

	pcr, err := readUint32(pcrBytes, origin, point)
	if err != nil {
		return nil, err
	}

	bType, err := readUint32(bTypeBytes, origin, point)
	if err != nil {
		return nil, err
	}

	digestBytes, err = readBytes(digestBytes, origin, point)
	if err != nil {
		return nil, err
	}

	dataLength, err := readUint32(dataLengthBytes, origin, point)
	if err != nil {
		return nil, err
	}

	dataBytes := make([]byte, dataLength)
	dataBytes, err = readBytes(dataBytes, origin, point)
	if err != nil {
		return nil, err
	}

	// real SHA1 BIOS event log in TPM1.2 doesn't have digest count and item. see detail in the doc
	result := &entity.BIOSManifestItem{
		Pcr:   pcr,
		BType: bType,
		Digest: entity.DigestValues{
			Count: 1,
			Item: []entity.DigestItem{
				{
					AlgID: SHA1_ALG_ID,
					Item:  hex.EncodeToString(digestBytes),
				},
			},
		},
		DataLen: dataLength,
		Data:    hex.EncodeToString(dataBytes),
	}
	return result, nil

}

func readBIOSEvent2Log(origin []byte, point *int64) (*entity.BIOSManifestItem, error) {
	const (
		PCR_LEN           int8 = 4
		BIOS_TYPE_LEN     int8 = 4
		DATA_LEN_LEN      int8 = 4
		DIGEST_COUNT_LEN  int8 = 4
		DIGEST_ALG_ID_LEN int8 = 2
		SHA1_DIGEST_LEN   int8 = 20
		SHA256_DIGEST_LEN int8 = 32
	)

	pcrBytes := make([]byte, PCR_LEN)
	bTypeBytes := make([]byte, BIOS_TYPE_LEN)
	dataLengthBytes := make([]byte, DATA_LEN_LEN)
	dCountBytes := make([]byte, DIGEST_COUNT_LEN)
	dAlgIDBytes := make([]byte, DIGEST_ALG_ID_LEN)

	pcr, err := readUint32(pcrBytes, origin, point)
	if err != nil {
		return nil, err
	}

	bType, err := readUint32(bTypeBytes, origin, point)
	if err != nil {
		return nil, err
	}

	dCount, err := readUint32(dCountBytes, origin, point)
	if err != nil {
		return nil, err
	}

	dv := entity.DigestValues{Count: dCount}
	for i := 0; i < int(dCount); i++ {
		dAlgIDBytes, err = readBytes(dAlgIDBytes, origin, point)
		if err != nil {
			return nil, err
		}
		algIdStr := hex.EncodeToString(dAlgIDBytes)
		if algIdStr == SHA1_ALG_ID {
			dBytes := make([]byte, SHA1_DIGEST_LEN)
			dBytes, err = readBytes(dBytes, origin, point)
			if err != nil {
				return nil, err
			}
			dv.Item = append(dv.Item, entity.DigestItem{
				AlgID: SHA1_ALG_ID,
				Item:  hex.EncodeToString(dBytes),
			})
		}
		if algIdStr == SHA256_ALG_ID {
			dBytes := make([]byte, SHA256_DIGEST_LEN)
			dBytes, err = readBytes(dBytes, origin, point)
			if err != nil {
				return nil, err
			}
			dv.Item = append(dv.Item, entity.DigestItem{
				AlgID: SHA256_ALG_ID,
				Item:  hex.EncodeToString(dBytes),
			})
		}
	}

	dataLength, err := readUint32(dataLengthBytes, origin, point)
	if err != nil {
		return nil, err
	}

	dataBytes := make([]byte, dataLength)
	dataBytes, err = readBytes(dataBytes, origin, point)
	if err != nil {
		return nil, err
	}
	result := &entity.BIOSManifestItem{
		Pcr:   pcr,
		BType: bType,
		Digest: entity.DigestValues{
			Count: dv.Count,
			Item:  dv.Item,
		},
		DataLen: dataLength,
		Data:    hex.EncodeToString(dataBytes),
	}
	return result, nil
}

func readBytes(target []byte, origin []byte, point *int64) ([]byte, error) {
	end := *point + int64(len(target))
	if *point > int64(len(origin)) || end > int64(len(origin)) {
		return nil, errors.New("end of file")
	}
	copy(target, origin[*point:end])
	*point += int64(len(target))
	return target, nil
}

func readUint32(target []byte, origin []byte, point *int64) (uint32, error) {
	end := *point + int64(len(target))
	if *point > int64(len(origin)) || end > int64(len(origin)) {
		return 0, errors.New("end of file")
	}
	copy(target, origin[*point:end])
	bb := bytes.NewBuffer(target)
	var result uint32
	err := binary.Read(bb, binary.LittleEndian, &result)
	if err != nil {
		return 0, err
	}
	*point += int64(len(target))
	return result, nil
}

func getSpecID(origin []byte) string {
	const (
		Spec_Len         = 16
		Spec_Start_Index = 32
		Spec_End_Index   = 48
	)
	result := make([]byte, Spec_Len)
	copy(result, origin[Spec_Start_Index:Spec_End_Index])
	return string(result)
}
