/*
Copyright (c) Huawei Technologies Co., Ltd. 2021.
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: wucaijun
Create: 2021-10-08
Description: Using grpc to implement the service API.
*/

package clientapi

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
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
	uint32Len                         = 4
	digestAlgIDLen                    = 2
	sha1DigestLen                     = 20
	sha256DigestLen                   = 32
	sha1AlgID                         = "0400"
	sha256AlgID                       = "0b00"
	sha1AlgStr                        = "sha1"
	sha256AlgStr                      = "sha256"
	event2SpecID                      = "Spec ID Event03"
	specLen                           = 16
	specStart                         = 32
	specEnd                           = 48
)

type service struct {
	UnimplementedRasServer
	cm *cache.CacheMgr
}

// GenerateEKCert handles the generation of the EK certificate for client
func (s *service) GenerateEKCert(ctx context.Context, in *GenerateEKCertRequest) (*GenerateEKCertReply, error) {
	log.Printf("Server: receive GenerateEKCert")
	c := config.GetDefault(config.ConfServer)
	ip, _ := entity.GetIP()
	template := x509.Certificate{
		SerialNumber:   big.NewInt(1),
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(10, 0, 0),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		IsCA:           false,
		MaxPathLenZero: true,
		IPAddresses:    []net.IP{net.ParseIP(ip)},
	}
	ekCert, err := pca.GenerateCertificate(&template, c.GetPcaKeyCert(), in.GetEkPub(), c.GetPcaPrivateKey())
	if err != nil {
		return &GenerateEKCertReply{}, err
	}
	return &GenerateEKCertReply{EkCert: ekCert}, nil
}

// GenerateIKCert handles the generation of the IK certificate for client
func (s *service) GenerateIKCert(ctx context.Context, in *GenerateIKCertRequest) (*GenerateIKCertReply, error) {
	log.Printf("Server: receive GenerateIKCert and encrypt it")
	c := config.GetDefault(config.ConfServer)
	ip, _ := entity.GetIP()
	template := x509.Certificate{
		SerialNumber:   big.NewInt(1),
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(1, 0, 0),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		IsCA:           false,
		MaxPathLenZero: true,
		IPAddresses:    []net.IP{net.ParseIP(ip)},
	}
	ikCertDer, err := pca.GenerateCertificate(&template, c.GetPcaKeyCert(), in.GetIkPub(), c.GetPcaPrivateKey())
	if err != nil {
		return &GenerateIKCertReply{}, err
	}
	ekCert, err := x509.ParseCertificate(in.GetEkCert())
	if err != nil {
		return nil, err
	}
	encIkCert, err := pca.EncryptIKCert(ekCert.PublicKey, ikCertDer, in.GetIkName())
	if err != nil {
		return nil, err
	}
	return &GenerateIKCertReply{
		EncryptedIC:     encIkCert.EncryptedCert,
		CredBlob:        encIkCert.SymKeyParams.CredBlob,
		EncryptedSecret: encIkCert.SymKeyParams.EncryptedSecret,
		EncryptAlg:      encIkCert.SymKeyParams.EncryptAlg,
		EncryptParam:    encIkCert.SymKeyParams.EncryptParam,
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

	return &RegisterClientReply{
		ClientId: clientID,
		ClientConfig: &ClientConfig{
			HbDurationSeconds:    int64(hd.Seconds()),
			TrustDurationSeconds: int64(td.Seconds()),
			DigestAlgorithm:      cfg.GetDigestAlgorithm(),
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

	c := s.cm.GetCache(in.GetClientId())
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
	// compare if alg is same as ras
	cfg := config.GetDefault(config.ConfServer)
	alg := report.GetPcrInfo().GetAlgorithm()
	if alg != cfg.GetDigestAlgorithm() {
		log.Printf("Server: the reported algorithm of client %v is wrong", report.GetClientId())
		return &SendReportReply{Result: false}, fmt.Errorf("the reported algorithm is wrong")
	}
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

		switch strings.ToLower(om.GetType()) {
		case "bios":
			mi, err = unmarshalBIOSManifest(om.GetItem())
		case "ima":
			mi, err = unmarshalIMAManifest(om.GetItem())
		default:
			err = fmt.Errorf("unsupported manifest type: %s", om.GetType())
		}
		if err != nil {
			return &SendReportReply{Result: false}, err
		}

		// if type has existed
		for _, tm := range tms {
			if om.GetType() == tm.Type {
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
			Values: tpvs,
			Quote: entity.PcrQuote{
				Quoted: report.GetPcrInfo().GetPcrQuote().GetQuoted(),
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

// DoGenerateEKCert generates an ek certificate from ras server for client.
func DoGenerateEKCert(addr string, in *GenerateEKCertRequest) (*GenerateEKCertReply, error) {
	ras, err := makesock(addr)
	if err != nil {
		log.Printf("%v", err)
		return nil, err
	}
	defer ras.conn.Close()
	defer ras.cancel()

	bk, err := ras.c.GenerateEKCert(ras.ctx, in)
	if err != nil {
		log.Printf("Client: invoke GenerateEKCert error %v", err)
		return nil, err
	}
	log.Printf("Client: invoke GenerateEKCert ok")
	return bk, nil
}

// DoGenerateIKCert generates an identity certificate from ras server for client.
func DoGenerateIKCert(addr string, in *GenerateIKCertRequest) (*GenerateIKCertReply, error) {
	ras, err := makesock(addr)
	if err != nil {
		log.Printf("%v", err)
		return nil, err
	}
	defer ras.conn.Close()
	defer ras.cancel()

	bk, err := ras.c.GenerateIKCert(ras.ctx, in)
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

func getHashValue(alg string, evt *entity.BIOSManifestItem) string {
	algMap := map[string]string{
		sha1AlgStr:   sha1AlgID,
		sha256AlgStr: sha256AlgID,
	}
	if algID, ok := algMap[alg]; ok {
		for _, hv := range evt.Digest.Item {
			if hv.AlgID == algID {
				return hv.Item
			}
		}
	}
	return ""
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
	if strings.Contains(SpecID, event2SpecID) {
		for i := 0; ; i++ {
			event2Log, err := readBIOSEvent2Log(content, &point)
			if err != nil {
				break
			}
			detail, err := json.Marshal(event2Log)
			if err != nil {
				break
			}

			result.Items = append(result.Items, entity.ManifestItem{
				Name:   fmt.Sprint(event2Log.BType, "-", i),
				Value:  getHashValue(sha256AlgStr, event2Log),
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
		//the file path name may contains space chars
		if len(items) > 5 {
			items[4] = strings.Join(items[4:], " ")
			items = items[:5]
		}
		switch len(items) {
		case 5:
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
				Value:  items[3],
				Detail: string(detail),
			})
		case 0, 1:
			continue
		default:
			return nil, errors.New("ima manifest format is wrong")
		}
	}
	return result, nil
}

func readSHA1BIOSEventLog(origin []byte, point *int64) (*entity.BIOSManifestItem, error) {
	pcr, err := readUint32(origin, point)
	if err != nil {
		return nil, err
	}
	bType, err := readUint32(origin, point)
	if err != nil {
		return nil, err
	}
	digestBytes := make([]byte, sha1DigestLen)
	digestBytes, err = readBytes(digestBytes, origin, point)
	if err != nil {
		return nil, err
	}
	dataLength, err := readUint32(origin, point)
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
					AlgID: sha1AlgID,
					Item:  hex.EncodeToString(digestBytes),
				},
			},
		},
		DataLen: dataLength,
		Data:    hex.EncodeToString(dataBytes),
	}
	return result, nil
}

func parseDigestValues(cnt uint32, origin []byte, point *int64) (*entity.DigestValues, error) {
	var err error
	dAlgIDBytes := make([]byte, digestAlgIDLen)
	dv := &entity.DigestValues{Count: cnt}
	for i := 0; i < int(cnt); i++ {
		dAlgIDBytes, err = readBytes(dAlgIDBytes, origin, point)
		if err != nil {
			return nil, err
		}
		algIDStr := hex.EncodeToString(dAlgIDBytes)
		if algIDStr == sha1AlgID {
			dBytes := make([]byte, sha1DigestLen)
			dBytes, err = readBytes(dBytes, origin, point)
			if err != nil {
				return nil, err
			}
			dv.Item = append(dv.Item, entity.DigestItem{
				AlgID: sha1AlgID,
				Item:  hex.EncodeToString(dBytes),
			})
		}
		if algIDStr == sha256AlgID {
			dBytes := make([]byte, sha256DigestLen)
			dBytes, err = readBytes(dBytes, origin, point)
			if err != nil {
				return nil, err
			}
			dv.Item = append(dv.Item, entity.DigestItem{
				AlgID: sha256AlgID,
				Item:  hex.EncodeToString(dBytes),
			})
		}
	}
	return dv, nil
}

func readBIOSEvent2Log(origin []byte, point *int64) (*entity.BIOSManifestItem, error) {
	pcr, err := readUint32(origin, point)
	if err != nil {
		return nil, err
	}
	bType, err := readUint32(origin, point)
	if err != nil {
		return nil, err
	}
	dCount, err := readUint32(origin, point)
	if err != nil {
		return nil, err
	}
	dv, err := parseDigestValues(dCount, origin, point)
	if err != nil {
		return nil, err
	}
	dataLength, err := readUint32(origin, point)
	if err != nil {
		return nil, err
	}
	dataBytes := make([]byte, dataLength)
	dataBytes, err = readBytes(dataBytes, origin, point)
	if err != nil {
		return nil, err
	}
	result := &entity.BIOSManifestItem{
		Pcr:     pcr,
		BType:   bType,
		Digest:  *dv,
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

func readUint32(origin []byte, point *int64) (uint32, error) {
	target := make([]byte, uint32Len)
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
	result := make([]byte, specLen)
	copy(result, origin[specStart:specEnd])
	return string(result)
}
