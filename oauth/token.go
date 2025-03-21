package oauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

func isSafeURL(url string) bool {
	return strings.HasPrefix(url, "https://")
}

func initialTokenRequest(authRequest ActiveAuthRequest, code, appURL, clientID string, clientSecretJWK string) (map[string]interface{}, error) {
	authServerURL := authRequest.AuthServerIss

	// Construct auth token request fields
	redirectURI := fmt.Sprintf("%s/callback", appURL)

	clientAssertion, err := SignJWT(clientSecretJWK, authServerURL, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to create client assertion JWT: %w", err)
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

	authServerMeta, err := fetchAuthServerMeta(authServerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch auth server metadata: %w", err)
	}

	tokenURL, ok := authServerMeta["token_endpoint"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to get token endpoint")
	}

	if !isSafeURL(tokenURL) {
		return nil, fmt.Errorf("unsafe token URL: %s", tokenURL)
	}

	dpopProof, err := CreateDPoPProof("POST", tokenURL, authRequest.DPoPAuthServerNonce, authRequest.DPoPPrivateJWK, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create DPoP proof: %w", err)
	}

	client := &http.Client{}
	reqBody, _ := json.Marshal(params)

	req, err := http.NewRequest("POST", tokenURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DPoP", dpopProof)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var respBody map[string]interface{}
	err = json.Unmarshal(bodyBytes, &respBody)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if resp.StatusCode == 400 {

		if respBody["error"] == "use_dpop_nonce" {
			newNonce := resp.Header.Get("DPoP-Nonce")

			dpopProof, err = CreateDPoPProof("POST", tokenURL, newNonce, authRequest.DPoPPrivateJWK, "")
			if err != nil {
				return nil, fmt.Errorf("failed to create new DPoP proof: %w", err)
			}

			req.Header.Set("DPoP", dpopProof)
			resp, err = client.Do(req)
			if err != nil {
				return nil, fmt.Errorf("failed to retry request: %w", err)
			}
			defer resp.Body.Close()
		}
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return respBody, nil
}
