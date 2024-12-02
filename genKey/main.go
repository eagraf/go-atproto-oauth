package main

import (
	"fmt"

	"github.com/potproject/atproto-oauth2-go-example/key"
)

func main() {
	// Generate Secret JWK
	secretJWK := key.GenerateSecretJWK()
	fmt.Printf("SECRET_JWK='%s'\n", secretJWK)
}
