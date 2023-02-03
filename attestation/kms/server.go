/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: wangli
Create:
Description:
*/

package kmsServer

import (
	"context"
	"fmt"
	"net"

	"gitee.com/openeuler/kunpengsecl/attestation/common/cryptotools"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/kcms/common"
	"github.com/gemalto/kmip-go"
	"github.com/gemalto/kmip-go/kmip14"
)

const (
	AesKeySize = 16
	AlgAES     = 0x0006
	AlgCBC     = 0x0042
)

var (
	masterKey = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	iv        = []byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
)

func CreateSessionKey(ctx context.Context, payload *kmip.CreateRequestPayload) (*kmip.CreateResponsePayload, error) {
	// kmip-go源码有个BUG，存tag时用的是canonical名，但读tag时却是用的string名，因此GetTag方法会报错！
	// 进行帐号密码身份认证处理,暂时省略
	account := payload.TemplateAttribute.Get(kmip14.TagDeviceIdentifier.CanonicalName())
	pass := payload.TemplateAttribute.Get(kmip14.TagPassword.CanonicalName())
	_ = account
	_ = pass
	// 根据主密钥ID查找相应主密钥并生成次级密钥
	masterKeyID := payload.TemplateAttribute.Get(kmip14.TagUniqueIdentifier.CanonicalName())
	skey, _ := cryptotools.GetRandomBytes(AesKeySize)
	encSKEY, err := cryptotools.SymmetricEncrypt(AlgAES, AlgCBC, masterKey, iv, skey)
	if err != nil {
		return nil, err
	}
	resp := &kmip.CreateResponsePayload{
		ObjectType: kmip14.ObjectTypeSymmetricKey,
	}
	resp.TemplateAttribute = &kmip.TemplateAttribute{}
	resp.TemplateAttribute.Append(kmip14.TagUniqueIdentifier, masterKeyID.AttributeValue.(string))
	resp.TemplateAttribute.Append(kmip14.TagSymmetricKey, skey)                // 密钥明文
	resp.TemplateAttribute.Append(kmip14.TagEncryptionKeyInformation, encSKEY) // 密钥密文
	// BUG处理,将tag改为string名
	id := resp.TemplateAttribute.Get(kmip14.TagUniqueIdentifier.CanonicalName())
	id.AttributeName = kmip14.TagUniqueIdentifier.String()
	return resp, nil
}

func DecryptSessionKey(ctx context.Context, payload *common.GetRequestPayload) (*common.GetResponsePayload, error) {
	// 进行帐号密码身份认证处理,暂时省略
	account := payload.TemplateAttribute.Get(kmip14.TagDeviceIdentifier.CanonicalName())
	pass := payload.TemplateAttribute.Get(kmip14.TagPassword.CanonicalName())
	_ = account
	_ = pass
	// 根据主密钥ID使用相应主密钥对密钥密文进行解密
	masterKeyID := payload.TemplateAttribute.Get(kmip14.TagUniqueIdentifier.CanonicalName())
	attr1 := payload.TemplateAttribute.Get(kmip14.TagEncryptionKeyInformation.CanonicalName())
	cipherText := attr1.AttributeValue.([]byte)
	skey, err := cryptotools.SymmetricDecrypt(AlgAES, AlgCBC, masterKey, iv, cipherText)
	if err != nil {
		return nil, err
	}
	resp := &common.GetResponsePayload{}
	resp.TemplateAttribute = &kmip.TemplateAttribute{}
	resp.TemplateAttribute.Append(kmip14.TagUniqueIdentifier, masterKeyID.AttributeValue.(string))
	resp.TemplateAttribute.Append(kmip14.TagSymmetricKey, skey)                   // 密钥明文
	resp.TemplateAttribute.Append(kmip14.TagEncryptionKeyInformation, cipherText) // 密钥密文
	return resp, nil
}

var srv *kmip.Server = nil

func ExampleServer() {
	if srv != nil {
		return
	}
	listener, err := net.Listen("tcp", "0.0.0.0:5696")
	if err != nil {
		panic(err)
	}
	fmt.Println("Start Server...")

	kmip.DefaultProtocolHandler.LogTraffic = true

	kmip.DefaultOperationMux.Handle(kmip14.OperationCreate, &kmip.CreateHandler{
		Create: CreateSessionKey,
	})
	kmip.DefaultOperationMux.Handle(kmip14.OperationGet, &common.GetHandler{
		Get: DecryptSessionKey,
	})
	srv = &kmip.Server{}
	if err = srv.Serve(listener); err != nil {
		fmt.Printf("fail to serve, %v\n", err)
	}
}

func StopServer() {
	if srv == nil {
		return
	}
	srv.Close()
	srv = nil
}
