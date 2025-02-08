package main

import (
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/joho/godotenv"
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
	proxyUrl := os.Getenv("PROXY_URL")

	inMemoryPersister := NewInMemoryPersister()

	cfg := Config{
		Protocol:  protocol,
		Host:      host,
		Port:      port,
		SecretJWK: secretJWK,
		ProxyUrl:  proxyUrl,
	}

	// Register handlers
	http.HandleFunc("/start", EntrypointHandler(cfg).ServeHTTP)
	http.HandleFunc("/login", LoginHandler(cfg, inMemoryPersister).ServeHTTP)
	http.HandleFunc("/callback", CallbackHandler(cfg, inMemoryPersister).ServeHTTP)
	http.HandleFunc("/jwks.json", JWKSHandler(cfg).ServeHTTP)
	http.HandleFunc("/client_metadata.json", ClientMetadataHandler(cfg).ServeHTTP)

	// Reverse proxy

	frontendUrl, err := url.Parse(cfg.ProxyUrl)
	if err != nil {
		log.Fatal("Invalid redirect URL")
	}

	backendUrl, err := url.Parse("http://localhost:5002")
	if err != nil {
		log.Fatal("Invalid backend URL")
	}

	http.HandleFunc("/backend/{rest...}", ProxyRoute(cfg, backendUrl, "/backend").ServeHTTP)
	http.HandleFunc("/{rest...}", ProxyRoute(cfg, frontendUrl, "").ServeHTTP)

	http.ListenAndServe(":"+port, nil)
}
