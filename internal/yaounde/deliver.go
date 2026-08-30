package yaounde

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DeliveryResult carries the verified peer acknowledgement receipt.
type DeliveryResult struct {
	// ReceiptSignature is the peer Ed25519 signature over
	// AckReceiptPreimage(releaseID, reportSHA256), verified against the
	// registered peer key before this result is returned.
	ReceiptSignature []byte
}

// Deliverer posts one sealed envelope document to the peer's configured
// endpoint and verifies the peer-signed acknowledgement. Delivery is
// at-least-once with the release_id as idempotency key; an acknowledgement
// is accepted only when the peer signature verifies. There is no simulated
// peer: every failure is returned, never retried silently here (retry is an
// explicit operator action on a FAILED release).
type Deliverer struct {
	client *http.Client
}

// NewDeliverer builds the delivery client with bounded timeouts.
func NewDeliverer(client *http.Client) *Deliverer {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &Deliverer{client: client}
}

type ackResponse struct {
	AckSignatureBase64 string `json:"ack_signature_base64"`
}

// Deliver posts sealedEnvelope to peer.EndpointURL. The response must be
// 2xx and carry a peer-signed acknowledgement of
// AckReceiptPreimage(releaseID, reportSHA256); anything else — transport
// failure, non-2xx, malformed or unverifiable ack — is an error and the
// caller marks the delivery FAILED. No ack is ever fabricated.
func (deliverer *Deliverer) Deliver(ctx context.Context, peer Peer, releaseID, reportSHA256 string, sealedEnvelope []byte) (DeliveryResult, error) {
	if peer.EndpointURL == "" {
		return DeliveryResult{}, ErrPeerNotConfigured
	}
	if peer.Status != PeerActive {
		return DeliveryResult{}, ErrPeerNotActive
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, peer.EndpointURL, bytes.NewReader(sealedEnvelope))
	if err != nil {
		return DeliveryResult{}, fmt.Errorf("build delivery request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Yaounde-Idempotency-Key", releaseID)
	request.Header.Set("X-Yaounde-Report-Sha256", reportSHA256)
	response, err := deliverer.client.Do(request)
	if err != nil {
		return DeliveryResult{}, fmt.Errorf("deliver to peer: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return DeliveryResult{}, fmt.Errorf("read peer ack: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return DeliveryResult{}, fmt.Errorf("peer endpoint answered %d", response.StatusCode)
	}
	var ack ackResponse
	if err := json.Unmarshal(body, &ack); err != nil {
		return DeliveryResult{}, fmt.Errorf("peer ack is not a JSON acknowledgement: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(ack.AckSignatureBase64)
	if err != nil {
		if signature, err = base64.RawStdEncoding.DecodeString(ack.AckSignatureBase64); err != nil {
			return DeliveryResult{}, fmt.Errorf("peer ack signature is not base64: %w", err)
		}
	}
	if len(signature) != ed25519.SignatureSize {
		return DeliveryResult{}, errors.New("peer ack signature is not an Ed25519 signature")
	}
	if len(peer.publicKey) != 32 {
		return DeliveryResult{}, errors.New("peer has no registered public key; ack cannot be verified")
	}
	if !ed25519.Verify(ed25519.PublicKey(peer.publicKey), AckReceiptPreimage(releaseID, reportSHA256), signature) {
		return DeliveryResult{}, ErrSignatureInvalid
	}
	return DeliveryResult{ReceiptSignature: signature}, nil
}
