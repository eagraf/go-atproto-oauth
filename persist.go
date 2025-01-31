package main

import "fmt"

// ActiveAuthRequest is the data structure that is persisted for each active auth request.
type ActiveAuthRequest struct {
	AuthServerIss       string `json:"authserver_iss"`
	PKCEVerifier        string `json:"pkce_verifier"`
	DPoPPrivateJWK      string `json:"dpop_private_jwk"`
	DPoPAuthServerNonce string `json:"dpop_authserver_nonce"`
	State               string `json:"state"`
}

// Persister saves and retrieves active auth requests.
type Persister interface {
	// GetActiveAuthRequest retrieves an active auth request by its state.
	GetActiveAuthRequest(state string) (ActiveAuthRequest, error)
	// SaveActiveAuthRequest saves an active auth request to the persisted auth request store.
	SaveActiveAuthRequest(state string, request ActiveAuthRequest) error
	// DeleteActiveAuthRequest deletes an active auth request from the persisted auth request store.
	DeleteActiveAuthRequest(state string) error
}

// InMemoryPersister is a simple in-memory implementation of the Persister interface. This is used for demo and testing purposes.
type InMemoryPersister struct {
	activeAuthRequests map[string]ActiveAuthRequest
}

func NewInMemoryPersister() *InMemoryPersister {
	return &InMemoryPersister{
		activeAuthRequests: make(map[string]ActiveAuthRequest),
	}
}

func (p *InMemoryPersister) GetActiveAuthRequest(state string) (ActiveAuthRequest, error) {
	request, ok := p.activeAuthRequests[state]
	if !ok {
		return ActiveAuthRequest{}, fmt.Errorf("active auth request with state %s not found", state)
	}
	return request, nil
}

func (p *InMemoryPersister) SaveActiveAuthRequest(state string, request ActiveAuthRequest) error {
	if _, ok := p.activeAuthRequests[state]; ok {
		return fmt.Errorf("active auth request with state %s already exists", state)
	}
	p.activeAuthRequests[state] = request
	return nil
}

func (p *InMemoryPersister) DeleteActiveAuthRequest(state string) error {
	if _, ok := p.activeAuthRequests[state]; !ok {
		return fmt.Errorf("active auth request with state %s not found", state)
	}
	delete(p.activeAuthRequests, state)
	return nil
}
