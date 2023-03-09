/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.
*/

package common

import (
	"context"

	"github.com/gemalto/kmip-go"
)

// GetRequestPayload means kms request information.
type GetRequestPayload struct {
	TemplateAttribute *kmip.TemplateAttribute
}

// GetResponsePayload means kms response information.
type GetResponsePayload struct {
	TemplateAttribute *kmip.TemplateAttribute
}

// GetHandler contains get function
// which gets request and returns response.
type GetHandler struct {
	Get func(ctx context.Context, payload *GetRequestPayload) (*GetResponsePayload, error)
}

// HandleItem handles request payload
// and returns kmip response batch item.
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
