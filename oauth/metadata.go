package oauth

type ClientMetadata struct {
	ClientID                    string   `json:"client_id"`                                 // required
	ApplicationType             string   `json:"application_type,omitempty"`                // optional
	GrantTypes                  []string `json:"grant_types"`                               // required
	Scope                       string   `json:"scope"`                                     // required
	ResponseTypes               []string `json:"response_types"`                            // required
	RedirectURIs                []string `json:"redirect_uris"`                             // required
	DPopBoundAccessTokens       bool     `json:"dpop_bound_access_tokens"`                  // required
	TokenEndpointAuthMethod     string   `json:"token_endpoint_auth_method,omitempty"`      // optional
	TokenEndpointAuthSigningAlg string   `json:"token_endpoint_auth_signing_alg,omitempty"` // optional
	JwksUri                     string   `json:"jwks_uri,omitempty"`                        // optional
	Jwks                        string   `json:"jwks,omitempty"`                            // optional

	// recommended
	ClientName string `json:"client_name,omitempty"` // optional
	ClientURI  string `json:"client_uri,omitempty"`  // optional
	LogoURI    string `json:"logo_uri,omitempty"`    // optional
	TosURI     string `json:"tos_uri,omitempty"`     // optional
	PolicyURI  string `json:"policy_uri,omitempty"`  // optional
}

func getClientMetadata(protocol string, apiEndpointPath string) ClientMetadata {
	return ClientMetadata{
		ClientName:                  "Demo Client",
		ClientURI:                   protocol + "://" + apiEndpointPath,
		ClientID:                    protocol + "://" + apiEndpointPath + "/client_metadata.json", // TODO handle localhost for development mode
		ApplicationType:             "web",
		GrantTypes:                  []string{"authorization_code", "refresh_token"},
		Scope:                       "atproto transition:generic",
		ResponseTypes:               []string{"code"},
		RedirectURIs:                []string{protocol + "://" + apiEndpointPath + "/callback"},
		DPopBoundAccessTokens:       true,
		TokenEndpointAuthMethod:     "private_key_jwt",
		TokenEndpointAuthSigningAlg: "ES256",
		JwksUri:                     protocol + "://" + apiEndpointPath + "/jwks.json",
	}
}
