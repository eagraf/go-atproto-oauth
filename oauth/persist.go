package oauth

import "fmt"

// ActiveAuthRequest is the data structure that is persisted for each active auth request.
type ActiveAuthRequest struct {
	AuthServerIss       string `json:"authserver_iss"`
	PKCEVerifier        string `json:"pkce_verifier"`
	DPoPPrivateJWK      string `json:"dpop_private_jwk"`
	DPoPAuthServerNonce string `json:"dpop_authserver_nonce"`
	State               string `json:"state"`
	Handle              string `json:"handle"`
	DID                 string `json:"did"`
	PDSURL              string `json:"pds_url"`
}

type Session struct {
	AccessToken    string `json:"access_token"`
	RefreshToken   string `json:"refresh_token"`
	State          string `json:"state"`
	Handle         string `json:"handle"`
	DID            string `json:"did"`
	PDSDomain      string `json:"pds_domain"`
	Expiry         int64  `json:"expiry"`
	DPoPPrivateJWK string `json:"dpop_private_jwk"`
}

// Persister saves and retrieves active auth requests.
type Persister interface {
	// GetActiveAuthRequest retrieves an active auth request by its state.
	GetActiveAuthRequest(state string) (ActiveAuthRequest, error)
	// SaveActiveAuthRequest saves an active auth request to the persisted auth request store.
	SaveActiveAuthRequest(state string, request ActiveAuthRequest) error
	// DeleteActiveAuthRequest deletes an active auth request from the persisted auth request store.
	DeleteActiveAuthRequest(state string) error

	// GetSession retrieves a session by its state.
	GetSession(state string) (Session, error)
	// SaveSession saves a session to the persisted session store.
	SaveSession(state string, session Session) error
	// DeleteSession deletes a session from the persisted session store.
	DeleteSession(state string) error
}

// InMemoryPersister is a simple in-memory implementation of the Persister interface. This is used for demo and testing purposes.
type InMemoryPersister struct {
	activeAuthRequests map[string]ActiveAuthRequest
	sessions           map[string]Session
}

func NewInMemoryPersister() *InMemoryPersister {
	return &InMemoryPersister{
		activeAuthRequests: make(map[string]ActiveAuthRequest),
		sessions:           make(map[string]Session),
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

func (p *InMemoryPersister) GetSession(state string) (Session, error) {
	session, ok := p.sessions[state]
	if !ok {
		return Session{}, fmt.Errorf("session with state %s not found", state)
	}
	return session, nil
}

func (p *InMemoryPersister) SaveSession(state string, session Session) error {
	if _, ok := p.sessions[state]; ok {
		return fmt.Errorf("session with state %s already exists", state)
	}
	p.sessions[state] = session
	return nil
}

func (p *InMemoryPersister) DeleteSession(state string) error {
	if _, ok := p.sessions[state]; !ok {
		return fmt.Errorf("session with state %s not found", state)
	}
	delete(p.sessions, state)
	return nil
}
