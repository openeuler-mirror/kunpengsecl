package kmsServer

import (
	context "context"
	"time"
	"testing"
	
	"gitee.com/openeuler/kunpengsecl/attestation/ras/kcms/common"
	"github.com/gemalto/kmip-go"
	"github.com/gemalto/kmip-go/kmip14"
)

const (
	hostkeyid = "hostkeyid"
)

func TestSessionKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	payload := kmip.CreateRequestPayload{
		ObjectType: kmip14.ObjectTypeSymmetricKey,
	}
	payload.TemplateAttribute = kmip.TemplateAttribute{}
	payload.TemplateAttribute.Append(kmip14.TagUniqueIdentifier, hostkeyid)
	retPayload, err := CreateSessionKey(ctx, &payload)
	if err != nil {
		t.Errorf("Test create session key error %v", err)
	}

	cipherText := retPayload.TemplateAttribute.Get(kmip14.TagEncryptionKeyInformation.CanonicalName())
	var decPayload common.GetRequestPayload
	decPayload.TemplateAttribute = &kmip.TemplateAttribute{}
	decPayload.TemplateAttribute.Append(kmip14.TagUniqueIdentifier, hostkeyid)
	decPayload.TemplateAttribute.Append(kmip14.TagEncryptionKeyInformation, cipherText.AttributeValue.([]byte))
	_, err = DecryptSessionKey(ctx, &decPayload)
	if err != nil {
		t.Errorf("Test decrypt session key error %v", err)
	}
}

