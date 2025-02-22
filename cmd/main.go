package main

import (
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/eagraf/go-atproto-oauth/oauth"
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
	pdsUrl := os.Getenv("PDS_URL")
	brokerUrl := os.Getenv("BROKER_URL")

	inMemoryPersister := oauth.NewInMemoryPersister()

	cfg := oauth.Config{
		Protocol:  protocol,
		Host:      host,
		Port:      port,
		SecretJWK: secretJWK,
		ProxyUrl:  proxyUrl,
		PDSURL:    pdsUrl,
		BrokerUrl: brokerUrl,
	}

	// Register handlers
	http.HandleFunc("/start", oauth.EntrypointHandler(cfg).ServeHTTP)
	http.HandleFunc("/login", oauth.LoginHandler(cfg, inMemoryPersister).ServeHTTP)
	http.HandleFunc("/callback", oauth.CallbackHandler(cfg, inMemoryPersister).ServeHTTP)
	http.HandleFunc("/jwks.json", oauth.JWKSHandler(cfg).ServeHTTP)
	http.HandleFunc("/client_metadata.json", oauth.ClientMetadataHandler(cfg).ServeHTTP)

	// Reverse proxy

	frontendUrl, err := url.Parse(cfg.ProxyUrl)
	if err != nil {
		log.Fatal("Invalid redirect URL")
	}

	backendUrl, err := url.Parse("http://localhost:5002")
	if err != nil {
		log.Fatal("Invalid backend URL")
	}

	http.HandleFunc("/backend/{rest...}", oauth.ProxyRoute(cfg, backendUrl, "/backend").ServeHTTP)
	http.HandleFunc("/{rest...}", oauth.ProxyRoute(cfg, frontendUrl, "").ServeHTTP)

	// Set up a broker for xrpc endpoints
	broker := oauth.NewTokenBroker(inMemoryPersister, cfg.SecretJWK, cfg.SecretJWK, cfg.Host)
	http.HandleFunc("/xrpc/{rest...}", broker.Endpoint())

	http.ListenAndServe(":"+port, nil)
}
