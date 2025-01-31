package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/joho/godotenv"

	"github.com/potproject/atproto-oauth2-go-example/par"
	"github.com/potproject/atproto-oauth2-go-example/resolve"
)

func main() {
	// dotenv
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	protocol := os.Getenv("PROTOCOL")
	host := os.Getenv("HOST")
	port := os.Getenv("PORT")
	secretJWK := os.Getenv("SECRET_JWK")

	inMemoryPersister := NewInMemoryPersister()

	cfg := Config{
		Protocol:  protocol,
		Host:      host,
		Port:      port,
		SecretJWK: secretJWK,
	}

	// Register handlers
	http.HandleFunc("/", EntrypointHandler(cfg).ServeHTTP)
	http.HandleFunc("/login", LoginHandler(cfg, inMemoryPersister).ServeHTTP)
	http.HandleFunc("/callback", CallbackHandler(cfg, inMemoryPersister).ServeHTTP)
	http.HandleFunc("/jwks.json", JWKSHandler(cfg).ServeHTTP)
	http.HandleFunc("/client_metadata.json", ClientMetadataHandler(cfg).ServeHTTP)

	http.ListenAndServe(":"+port, nil)
}

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

func getClientMetadata(protocol string, host string, port string) ClientMetadata {
	return ClientMetadata{
		ClientName:                  "Demo Client",
		ClientURI:                   protocol + "://" + host,
		ClientID:                    protocol + "://" + host + "/client_metadata.json", // TODO handle localhost for development mode
		ApplicationType:             "web",
		GrantTypes:                  []string{"authorization_code", "refresh_token"},
		Scope:                       "atproto transition:generic",
		ResponseTypes:               []string{"code"},
		RedirectURIs:                []string{protocol + "://" + host + "/callback"},
		DPopBoundAccessTokens:       true,
		TokenEndpointAuthMethod:     "private_key_jwt",
		TokenEndpointAuthSigningAlg: "ES256",
		JwksUri:                     protocol + "://" + host + "/jwks.json",
	}
}

func initialTokenRequest(authRequest ActiveAuthRequest, code, appURL, clientID string, clientSecretJWK string) (map[string]interface{}, string, error) {
	authServerURL := authRequest.AuthServerIss

	// Construct auth token request fields
	redirectURI := fmt.Sprintf("%s/callback", appURL)

	clientAssertion, err := par.SignJWT(clientSecretJWK, authServerURL, clientID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create client assertion JWT: %w", err)
	}

	params := map[string]string{
		"client_id":             clientID,
		"redirect_uri":          redirectURI,
		"grant_type":            "authorization_code",
		"code":                  code,
		"code_verifier":         authRequest.PKCEVerifier,
		"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		"client_assertion":      clientAssertion,
	}

	authServerMeta, err := resolve.FetchAuthServerMeta(authServerURL)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch auth server metadata: %w", err)
	}

	tokenURL, ok := authServerMeta["token_endpoint"].(string)
	if !ok {
		return nil, "", fmt.Errorf("failed to get token endpoint")
	}

	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch token endpoint: %w", err)
	}
	if !isSafeURL(tokenURL) {
		return nil, "", fmt.Errorf("unsafe token URL: %s", tokenURL)
	}

	dpopProof, err := par.CreateDPoPProof("POST", tokenURL, authRequest.DPoPAuthServerNonce, authRequest.DPoPPrivateJWK)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create DPoP proof: %w", err)
	}

	client := &http.Client{}
	reqBody, _ := json.Marshal(params)

	req, err := http.NewRequest("POST", tokenURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DPoP", dpopProof)

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read response body: %w", err)
	}

	var respBody map[string]interface{}
	err = json.Unmarshal(bodyBytes, &respBody)
	if err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if resp.StatusCode == 400 {

		if respBody["error"] == "use_dpop_nonce" {
			newNonce := resp.Header.Get("DPoP-Nonce")
			fmt.Printf("retrying with new auth server DPoP nonce: %s\n", newNonce)

			dpopProof, err = par.CreateDPoPProof("POST", tokenURL, newNonce, authRequest.DPoPPrivateJWK)
			if err != nil {
				return nil, "", fmt.Errorf("failed to create new DPoP proof: %w", err)
			}

			req.Header.Set("DPoP", dpopProof)
			resp, err = client.Do(req)
			if err != nil {
				return nil, "", fmt.Errorf("failed to retry request: %w", err)
			}
			defer resp.Body.Close()
		}
	}

	if resp.StatusCode >= 400 {
		return nil, "", fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return respBody, authRequest.DPoPAuthServerNonce, nil
}

func isSafeURL(url string) bool {
	return strings.HasPrefix(url, "https://")
}
