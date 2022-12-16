package common

import (
	"context"

	"github.com/gemalto/kmip-go"
)

// GetRequestPayload ////////////////////////////////////////
type GetRequestPayload struct {
	TemplateAttribute *kmip.TemplateAttribute
}

// GetResponsePayload
type GetResponsePayload struct {
	TemplateAttribute *kmip.TemplateAttribute
}

type GetHandler struct {
	Get func(ctx context.Context, payload *GetRequestPayload) (*GetResponsePayload, error)
}

func (h *GetHandler) HandleItem(ctx context.Context, req *kmip.Request) (*kmip.ResponseBatchItem, error) {
	var payload GetRequestPayload

	err := req.DecodePayload(&payload)
	if err != nil {
		return nil, err
	}

	respPayload, err := h.Get(ctx, &payload)
	if err != nil {
		return nil, err
	}

	// req.Key = respPayload.Key

	return &kmip.ResponseBatchItem{
		ResponsePayload: respPayload,
	}, nil
}
