package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/joho/godotenv"

	"github.com/potproject/atproto-oauth2-go-example/key"
	"github.com/potproject/atproto-oauth2-go-example/par"
	"github.com/potproject/atproto-oauth2-go-example/resolve"
)

func main() {
	// dotenv
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	host := os.Getenv("HOST")
	port := os.Getenv("PORT")
	secretJWK := os.Getenv("SECRET_JWK")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
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
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		// Resolve did -> pds
		pds, err := resolve.PDS(did)
		if err != nil {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		// Resolve PDS Auth server
		authServer, err := resolve.PDSAuthServer(pds)
		if err != nil {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		// resolve PAR(Pushed Authorization Requests) server
		parServer, err := resolve.PARServer(authServer)
		if err != nil {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		// get Client Metadata
		clientMetadata := getClientMetadata(host)

		// PAR request
		requestUri, err := par.Par(parServer, authServer, secretJWK, clientMetadata.ClientID, clientMetadata.RedirectURIs[0])
		if err != nil {
			fmt.Println(err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Redirect to auth server
		authServerEndpoint, err := getAuthServerAuthEndpoint(authServer)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		data := url.Values{}
		data.Set("client_id", clientMetadata.ClientID)
		data.Set("request_uri", requestUri)
		http.Redirect(w, r, authServerEndpoint+"?"+data.Encode(), http.StatusFound)
	})

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// display get parameter
		iss := r.URL.Query().Get("iss")
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		w.Write([]byte("<html><body>"))
		w.Write([]byte("<h1>Callback</h1>"))
		w.Write([]byte("<p>iss: " + iss + "</p>"))
		w.Write([]byte("<p>code: " + code + "</p>"))
		w.Write([]byte("<p>state: " + state + "</p>"))
		w.Write([]byte("</body></html>"))
	})

	http.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		publicJWK, err := key.PrivateJWKtoPublicJWK(secretJWK)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys":[`))
		w.Write([]byte(publicJWK))
		w.Write([]byte(`]}`))
	})

	http.HandleFunc("/client_metadata.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		clientMetadata := getClientMetadata(host)
		clientMetadataJSON, err := json.Marshal(clientMetadata)
		if err != nil {
			http.Error(w, "Not Found", http.StatusNotFound)
		}
		w.Write(clientMetadataJSON)
	})

	err = http.ListenAndServe(":"+port, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
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

func getClientMetadata(host string) ClientMetadata {
	return ClientMetadata{
		ClientName:                  "Demo Client",
		ClientURI:                   "https://" + host,
		ClientID:                    "https://" + host + "/client_metadata.json",
		ApplicationType:             "web",
		GrantTypes:                  []string{"authorization_code", "refresh_token"},
		Scope:                       "atproto transition:generic",
		ResponseTypes:               []string{"code"},
		RedirectURIs:                []string{"https://" + host + "/callback"},
		DPopBoundAccessTokens:       true,
		TokenEndpointAuthMethod:     "private_key_jwt",
		TokenEndpointAuthSigningAlg: "ES256",
		JwksUri:                     "https://" + host + "/jwks.json",
	}
}

func getAuthServerAuthEndpoint(server string) (string, error) {
	resp, err := http.Get(server + "/.well-known/oauth-authorization-server")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var serverMetadata map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&serverMetadata)
	if err != nil {
		return "", err
	}

	endpoint, ok := serverMetadata["authorization_endpoint"].(string)
	if !ok {
		return "", fmt.Errorf("failed to parse authorization_endpoint")
	}

	return endpoint, nil
}
