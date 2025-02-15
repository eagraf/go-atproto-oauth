package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// TokenBroker handles attaching OAuth tokens and DPoP proofs to requests
type TokenBroker struct {
	persister Persister

	// JWK private key
	dpopPrivateKey string
	dpopPublicJWK  string
	dpopNonce      string
	issuer         string
}

// NewTokenBroker creates a new token broker instance
func NewTokenBroker(persister Persister, dpopPrivateKey string, dpopPublicJWK string, issuer string) *TokenBroker {
	return &TokenBroker{
		persister:      persister,
		dpopPrivateKey: dpopPrivateKey,
		dpopPublicJWK:  dpopPublicJWK,
		issuer:         issuer,
	}
}

func (b *TokenBroker) Endpoint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Broker endpoint hit")

		err := b.wrapRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		resp, err := b.forwardRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		defer resp.Body.Close()
		io.Copy(w, resp.Body)

		for k, v := range resp.Header {
			w.Header().Set(k, v[0])
		}

		w.WriteHeader(resp.StatusCode)
	}
}

// WrapRequest wraps an HTTP request with OAuth token and DPoP proof
func (b *TokenBroker) wrapRequest(req *http.Request) error {
	// Clear out request uri
	// https://stackoverflow.com/questions/19595860/http-request-requesturi-field-when-making-request-in-go
	req.RequestURI = ""

	// Get state from cookie
	stateCookie, err := req.Cookie("state")
	if err != nil {
		return fmt.Errorf("error getting state cookie: %w", err)
	}

	state := stateCookie.Value

	session, err := b.persister.GetSession(state)
	if err != nil {
		return fmt.Errorf("error getting active auth request: %w", err)
	}

	// Use session to build request url
	req.URL.Scheme = "https"
	req.URL.Host = session.PDSDomain

	// Generate DPoP proof
	dpopProof, err := CreateDPoPProof(req.Method, req.URL.String(), b.dpopNonce, b.dpopPrivateKey)
	if err != nil {
		return fmt.Errorf("error creating DPoP proof: %w", err)
	}

	// Add Authorization and DPoP headers
	req.Header.Set("Authorization", "DPoP "+session.AccessToken)
	req.Header.Set("DPoP", dpopProof)

	return nil
}

// Do performs an HTTP request with OAuth token and DPoP proof
func (b *TokenBroker) forwardRequest(req *http.Request) (*http.Response, error) {
	// Clone request body if present
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	err := b.wrapRequest(req)
	if err != nil {
		return nil, err
	}

	// Make request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	// Handle DPoP nonce error
	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized {
		var errorResp struct {
			Error string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
			return resp, nil
		}
		resp.Body.Close()

		if errorResp.Error == "use_dpop_nonce" {
			// Update nonce and retry
			b.dpopNonce = resp.Header.Get("DPoP-Nonce")

			// Recreate request with original body
			if bodyBytes != nil {
				req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}

			err = b.wrapRequest(req)
			if err != nil {
				return nil, err
			}

			return b.forwardRequest(req)
		}
	}

	return resp, nil
}
