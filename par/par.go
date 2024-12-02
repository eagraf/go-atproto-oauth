package par

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/potproject/atproto-oauth2-go-example/key"
)

func generateToken() string {
	rand.Seed(time.Now().UnixNano())
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func codeVerifier() string {
	rand.Seed(time.Now().UnixNano())
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	b := make([]byte, 64)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func codeChallenge(verifier string) string {
	h := sha256.New()
	h.Write([]byte(verifier))
	hash := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(hash)
}

type Claims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
	Jti string `json:"jti"`
}

type DPoPClaims struct {
	Jti   string `json:"jti"`
	Htm   string `json:"htm"`
	Htu   string `json:"htu"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
	Nonce string `json:"nonce"`
}

func signJWT(privateJWK string, authServer string, clientID string) (string, error) {
	// Parse the private key JWK
	var jwk jose.JSONWebKey
	err := json.Unmarshal([]byte(privateJWK), &jwk)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key JWK: %v", err)
	}

	// Create a new signer
	signingKey := jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key}
	signer, err := jose.NewSigner(signingKey, (&jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": jwk.KeyID,
		},
	}).WithType("JWT"))
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %v", err)
	}

	// Create claims
	now := time.Now()
	claims := Claims{
		Iss: clientID,
		Sub: clientID,
		Aud: authServer,
		Exp: now.Add(5 * time.Minute).Unix(),
		Iat: now.Unix(),
		Jti: generateToken(),
	}

	// Marshal claims to JSON
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %v", err)
	}

	// Sign the claims
	object, err := signer.Sign(claimsJSON)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %v", err)
	}

	// Serialize the signed object
	token, err := object.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize token: %v", err)
	}

	return token, nil
}

func createDPoPProof(method string, url string, nonce string, privateJWK string) (string, error) {
	var jwk jose.JSONWebKey
	err := json.Unmarshal([]byte(privateJWK), &jwk)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key JWK: %v", err)
	}

	// Get public key
	publicKey := jwk.Public()
	publicJWKMap := make(map[string]interface{})
	publicJWKBytes, err := publicKey.MarshalJSON()
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %v", err)
	}
	err = json.Unmarshal(publicJWKBytes, &publicJWKMap)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal public key: %v", err)
	}

	// Create signer with custom header
	opts := &jose.SignerOptions{}
	opts.WithHeader("typ", "dpop+jwt")
	opts.WithHeader("jwk", publicJWKMap)

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key}, opts)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %v", err)
	}

	now := time.Now()
	claims := DPoPClaims{
		Jti:   generateToken(),
		Htm:   method,
		Htu:   url,
		Iat:   now.Unix(),
		Exp:   now.Add(30 * time.Second).Unix(),
		Nonce: nonce,
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %v", err)
	}

	object, err := signer.Sign(claimsJSON)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %v", err)
	}

	token, err := object.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize token: %v", err)
	}

	return token, nil
}

type PARResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

func parRequest(endpoint string, state string, codeChallenge string, clientAssertion string, dpopProof string, clientID string, redirectUrl string) (jsonBody map[string]interface{}, dpopNonce string, err error) {
	// Make PAR request
	parData := url.Values{}
	parData.Set("client_id", clientID)
	parData.Set("response_type", "code")
	parData.Set("code_challenge", codeChallenge)
	parData.Set("code_challenge_method", "S256")
	parData.Set("redirect_uri", redirectUrl)
	parData.Set("scope", "atproto transition:generic")
	parData.Set("state", state)
	parData.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	parData.Set("client_assertion", clientAssertion)

	// http request post
	client := &http.Client{}
	req, err := http.NewRequest("POST", endpoint, strings.NewReader(parData.Encode()))
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", dpopProof)

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to make request: %v", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read response: %v", err)
	}

	result := make(map[string]interface{})
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse response: %v", err)
	}

	responseError, ok := result["error"].(string)
	if !ok {
		return result, "", nil
	}

	if resp.StatusCode == http.StatusBadRequest && responseError == "use_dpop_nonce" {
		dpopNonce = resp.Header.Get("DPoP-Nonce")
		return nil, dpopNonce, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("PAR request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return result, "", nil
}

func Par(parServer string, authServer string, privateJWK string, clientID string, redirectUrl string) (string, error) {
	state := generateToken()
	codeVerifier := codeVerifier()
	codeChallenge := codeChallenge(codeVerifier)

	// Sign JWT for client authentication
	clientAssertion, err := signJWT(privateJWK, authServer, clientID)
	if err != nil {
		return "", fmt.Errorf("failed to create client assertion: %v", err)
	}

	// DPoP Proof
	dpopPrivateJWK := key.GenerateSecretJWK()

	// Create DPoP proof
	dpopProof, err := createDPoPProof("POST", parServer, "", dpopPrivateJWK)
	if err != nil {
		return "", fmt.Errorf("failed to create DPoP proof: %v", err)
	}

	// Make PAR request
	d, dpopNonce, err := parRequest(parServer, state, codeChallenge, clientAssertion, dpopProof, clientID, redirectUrl)
	if err != nil {
		return "", fmt.Errorf("failed to make PAR request: %v", err)
	}

	if dpopNonce != "" {
		// Create DPoP proof with nonce
		dpopProof, err = createDPoPProof("POST", parServer, dpopNonce, dpopPrivateJWK)
		if err != nil {
			return "", fmt.Errorf("failed to create DPoP proof: %v", err)
		}
		d, _, err := parRequest(parServer, state, codeChallenge, clientAssertion, dpopProof, clientID, redirectUrl)
		if err != nil {
			return "", fmt.Errorf("failed to make PAR request: %v", err)
		}
		return d["request_uri"].(string), nil
	}

	requestUri, ok := d["request_uri"].(string)
	if !ok {
		return "", fmt.Errorf("failed to parse request_uri")
	}

	return requestUri, nil
}
