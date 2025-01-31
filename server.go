package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/potproject/atproto-oauth2-go-example/key"
	"github.com/potproject/atproto-oauth2-go-example/par"
	"github.com/potproject/atproto-oauth2-go-example/resolve"
)

type Config struct {
	Protocol  string
	Host      string
	Port      string
	SecretJWK string
}

func EntrypointHandler(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Post DID and submit
		w.Write([]byte("<html><body>"))
		w.Write([]byte("<h1>Login</h1>"))
		w.Write([]byte("<form action=\"/login\" method=\"post\">"))
		w.Write([]byte("<label for=\"did\">handle:</label>"))
		w.Write([]byte("<input type=\"text\" id=\"handle\" name=\"handle\"><br><br>"))
		w.Write([]byte("<input type=\"submit\" value=\"Submit\">"))
		w.Write([]byte("</form>"))
		w.Write([]byte("</body></html>"))
	})
}

func LoginHandler(cfg Config, persister Persister) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Post Only
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get handle
		handle := r.FormValue("handle")
		if handle == "" {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Resolve handle -> did
		did, err := resolve.Handle(handle)
		if err != nil {
			http.Error(w, fmt.Sprintf("Not Found: %s", err), http.StatusNotFound)
			return
		}

		// Resolve did -> pds
		pds, err := resolve.PDS(did)
		if err != nil {
			http.Error(w, fmt.Sprintf("Not Found: %s", err), http.StatusNotFound)
			return
		}

		// Resolve PDS Auth server
		authServer, err := resolve.PDSAuthServer(pds)
		if err != nil {
			http.Error(w, fmt.Sprintf("Not Found: %s", err), http.StatusNotFound)
			return
		}

		// resolve PAR(Pushed Authorization Requests) server
		authServerMeta, err := resolve.FetchAuthServerMeta(authServer)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error fetching auth server metadata: %s", err), http.StatusInternalServerError)
			return
		}

		parServer, ok := authServerMeta["pushed_authorization_request_endpoint"].(string)
		if !ok {
			http.Error(w, fmt.Sprintf("Error getting PAR endpoint: %s", err), http.StatusInternalServerError)
			return
		}

		// get Client Metadata
		clientMetadata := getClientMetadata(cfg.Protocol, cfg.Host, cfg.Port)

		dpopPrivateJWK := key.GenerateSecretJWK()

		// PAR request
		requestUri, codeVerifier, state, dpopNonce, err := par.Par(parServer, authServer, cfg.SecretJWK, clientMetadata.ClientID, clientMetadata.RedirectURIs[0], dpopPrivateJWK)
		if err != nil {
			fmt.Println(err)
			http.Error(w, fmt.Sprintf("Internal Server Error: %s", err), http.StatusInternalServerError)
			return
		}

		err = persister.SaveActiveAuthRequest(state, ActiveAuthRequest{
			AuthServerIss:       authServer,
			PKCEVerifier:        codeVerifier,
			DPoPPrivateJWK:      dpopPrivateJWK,
			DPoPAuthServerNonce: dpopNonce,
			State:               state,
		})
		if err != nil {
			http.Error(w, fmt.Sprintf("Internal Server Error: %s", err), http.StatusInternalServerError)
			return
		}

		// Redirect to auth server

		authServerEndpoint, ok := authServerMeta["authorization_endpoint"].(string)
		if !ok {
			http.Error(w, fmt.Sprintf("Error getting auth server endpoint: %s", err), http.StatusInternalServerError)
			return
		}

		data := url.Values{}
		data.Set("client_id", clientMetadata.ClientID)
		data.Set("request_uri", requestUri)
		http.Redirect(w, r, authServerEndpoint+"?"+data.Encode(), http.StatusFound)
	})
}

func CallbackHandler(cfg Config, persister Persister) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// display get parameter
		iss := r.URL.Query().Get("iss")
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		authRequest, err := persister.GetActiveAuthRequest(state)
		if err != nil {
			http.Error(w, fmt.Sprintf("Not Found: %s", state), http.StatusNotFound)
			return
		}

		err = persister.DeleteActiveAuthRequest(state)
		if err != nil {
			http.Error(w, fmt.Sprintf("Internal Server Error: %s", err), http.StatusInternalServerError)
			return
		}

		clientMetadata := getClientMetadata(cfg.Protocol, cfg.Host, cfg.Port)
		clientID := clientMetadata.ClientID

		tokenBody, nonce, err := initialTokenRequest(authRequest, code, cfg.Protocol+"://"+cfg.Host, clientID, cfg.SecretJWK)
		if err != nil {
			http.Error(w, fmt.Sprintf("Internal Server Error: %s", err), http.StatusInternalServerError)
			return
		}

		w.Write([]byte("<html><body>"))
		w.Write([]byte("<h1>Callback</h1>"))
		w.Write([]byte("<p>iss: " + iss + "</p>"))
		w.Write([]byte("<p>code: " + code + "</p>"))
		w.Write([]byte("<p>state: " + state + "</p>"))
		w.Write([]byte("<p>token: " + fmt.Sprintf("%+v", tokenBody) + "</p>"))
		w.Write([]byte("<p>nonce: " + nonce + "</p>"))
		w.Write([]byte("</body></html>"))
	})
}

func JWKSHandler(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		publicJWK, err := key.PrivateJWKtoPublicJWK(cfg.SecretJWK)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys":[`))
		w.Write([]byte(publicJWK))
		w.Write([]byte(`]}`))
	})
}

func ClientMetadataHandler(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		clientMetadata := getClientMetadata(cfg.Protocol, cfg.Host, cfg.Port)
		clientMetadataJSON, err := json.Marshal(clientMetadata)
		if err != nil {
			http.Error(w, "Not Found", http.StatusNotFound)
		}
		w.Write(clientMetadataJSON)
	})
}
