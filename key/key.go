package key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"github.com/square/go-jose"
)

func PrivateJWKtoPublicJWK(privateJWK string) (string, error) {
	var jwk jose.JSONWebKey
	err := json.Unmarshal([]byte(privateJWK), &jwk)

	if err != nil {
		return "", fmt.Errorf("failed to parse private key JWK: %v", err)
	}

	publicKey := jwk.Public()
	publicJWK, err := json.Marshal(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key JWK: %v", err)
	}
	return string(publicJWK), nil
}

func GenerateSecretJWK() string {
	now := time.Now().Unix()

	// Generate ECDSA　Private Key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// Generate JWK Object
	jwk := jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     fmt.Sprintf("demo-%d", now),
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}

	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		panic(err)
	}

	return string(jwkJSON)
}
