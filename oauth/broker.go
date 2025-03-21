package oauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// TokenBroker handles attaching OAuth tokens and DPoP proofs to requests
type TokenBroker struct {
	persister Persister
	// JWK private key
	issuer string
	// The URL habitat actually internally proxies to.
	internalURL string
	// Used to match the htu claim on the PDS Oauth server
	externalURL string
}

// NewTokenBroker creates a new token broker instance
func NewTokenBroker(persister Persister, issuer string, internalURL string, externalURL string) *TokenBroker {
	return &TokenBroker{
		persister:   persister,
		issuer:      issuer,
		internalURL: internalURL,
		externalURL: externalURL,
	}
}

func (b *TokenBroker) Endpoint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		resp, err := b.dpopRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Copy response headers before writing status code
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)

		// Write body last
		defer resp.Body.Close()
		io.Copy(w, resp.Body)
	}
}

// WrapRequest wraps an HTTP request with OAuth token and DPoP proof
func (b *TokenBroker) wrapRequest(req *http.Request, dpopNonce string) error {
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
	newURL, err := url.Parse(b.internalURL)
	if err != nil {
		return fmt.Errorf("error parsing base URL: %w", err)
	}
	req.URL.Host = newURL.Host
	req.URL.Scheme = newURL.Scheme

	// Note: the htu claim must match the URL of the OAuth server we are hitting.
	// Use the external URL, because the internal URL may not match when there is a proxy in between.
	htu, err := url.Parse(b.externalURL)
	if err != nil {
		return fmt.Errorf("error parsing external URL: %w", err)
	}
	htu.Path = req.URL.Path

	// Generate DPoP proof
	dpopProof, err := CreateDPoPProof(req.Method, htu.String(), dpopNonce, session.DPoPPrivateJWK, session.AccessToken)
	if err != nil {
		return fmt.Errorf("error creating DPoP proof: %w", err)
	}

	// Add Authorization and DPoP headers
	req.Header.Set("Authorization", "DPoP "+session.AccessToken)
	req.Header.Set("DPoP", dpopProof)

	return nil
}

// Do performs an HTTP request with OAuth token and DPoP proof
func (b *TokenBroker) dpopRequest(req *http.Request) (*http.Response, error) {
	bodyBytes := []byte{}
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	resp, err := b.forwardRequest(req, bodyBytes, "")
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
			dpopNonce := resp.Header.Get("DPoP-Nonce")

			return b.forwardRequest(req, bodyBytes, dpopNonce)
		}
	}

	return resp, nil
}

func (b *TokenBroker) forwardRequest(req *http.Request, bodyBytes []byte, dpopNonce string) (*http.Response, error) {
	req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	err := b.wrapRequest(req, dpopNonce)
	if err != nil {
		return nil, err
	}

	// Make request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
