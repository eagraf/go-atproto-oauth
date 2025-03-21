package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"

	"github.com/potproject/atproto-oauth2-go-example/key"
)

type Config struct {
	Protocol     string
	Host         string
	SecretJWK    string
	PDSURL       string
	BrokerUrl    string
	EndpointPath string
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5002") // Change to match frontend
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Credentials", "true") // ✅ Allows cookies

		// Handle preflight (OPTIONS) request
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}

func ProxyRoute(cfg Config, targetURL *url.URL, routePrefix string) http.Handler {
	return corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create reverse proxy
		proxy := &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL.Scheme = targetURL.Scheme
				req.URL.Host = targetURL.Host

				req.URL.Path = path.Join(targetURL.Path, strings.TrimPrefix(req.URL.Path, routePrefix))
			},
		}

		// Forward the request
		proxy.ServeHTTP(w, r)
	}))
}

func EntrypointHandler(cfg Config) http.Handler {
	return corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
}

func LoginHandler(cfg Config, persister Persister) http.Handler {
	return corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		// Resolve did -> pds
		pds, did, err := getPDSURL(handle, cfg)
		if err != nil {
			http.Error(w, fmt.Sprintf("Not Found: %s", err), http.StatusNotFound)
			return
		}

		// Resolve PDS Auth server
		authServer, err := resolvePDSAuthServer(pds)
		if err != nil {
			http.Error(w, fmt.Sprintf("Not Found: %s", err), http.StatusNotFound)
			return
		}

		// resolve PAR(Pushed Authorization Requests) server
		authServerMeta, err := fetchAuthServerMeta(authServer)
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
		clientMetadata := getClientMetadata(cfg.Protocol, path.Join(cfg.Host, cfg.EndpointPath))

		dpopPrivateJWK := key.GenerateSecretJWK()

		// PAR request
		authRequest, requestUri, err := Par(parServer, authServer, cfg.SecretJWK, clientMetadata.ClientID, clientMetadata.RedirectURIs[0], dpopPrivateJWK)
		if err != nil {
			http.Error(w, fmt.Sprintf("Internal Server Error: %s", err), http.StatusInternalServerError)
			return
		}

		// Populate additional fields we want to save with the auth request
		authRequest.Handle = handle
		authRequest.DID = did
		authRequest.PDSURL = pds

		err = persister.SaveActiveAuthRequest(authRequest.State, *authRequest)
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
	}))
}

func CallbackHandler(cfg Config, persister Persister) http.Handler {
	return corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// display get parameter
		//iss := r.URL.Query().Get("iss")
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

		clientMetadata := getClientMetadata(cfg.Protocol, path.Join(cfg.Host, cfg.EndpointPath))
		clientID := clientMetadata.ClientID

		tokenBody, err := initialTokenRequest(authRequest, code, cfg.Protocol+"://"+path.Join(cfg.Host, cfg.EndpointPath), clientID, cfg.SecretJWK)
		if err != nil {
			http.Error(w, fmt.Sprintf("Internal Server Error: %s", err), http.StatusInternalServerError)
			return
		}

		pdsDomain := strings.Replace(strings.Replace(authRequest.PDSURL, "https://", "", 1), "http://", "", 1)

		session := Session{
			AccessToken:    tokenBody["access_token"].(string),
			RefreshToken:   tokenBody["refresh_token"].(string),
			State:          state,
			Handle:         authRequest.Handle,
			DID:            authRequest.DID,
			PDSDomain:      pdsDomain,
			DPoPPrivateJWK: authRequest.DPoPPrivateJWK,
		}
		err = persister.SaveSession(state, session)
		if err != nil {
			http.Error(w, fmt.Sprintf("Internal Server Error: %s", err), http.StatusInternalServerError)
			return
		}

		pdsUrl := authRequest.PDSURL
		if cfg.BrokerUrl != "" {
			pdsUrl = cfg.BrokerUrl
		}

		// Set secure cookies for auth data
		http.SetCookie(w, &http.Cookie{
			Name:     "did",
			Value:    authRequest.DID,
			Path:     "/",
			Secure:   true,
			HttpOnly: false,
			SameSite: http.SameSiteLaxMode,
			Domain:   cfg.Host,
		})

		http.SetCookie(w, &http.Cookie{
			Name:     "handle",
			Value:    authRequest.Handle,
			Path:     "/",
			Secure:   true,
			HttpOnly: false,
			SameSite: http.SameSiteLaxMode,
			Domain:   cfg.Host,
		})

		http.SetCookie(w, &http.Cookie{
			Name:     "pds_url",
			Value:    pdsUrl,
			Path:     "/",
			Secure:   true,
			HttpOnly: false,
			SameSite: http.SameSiteLaxMode,
			Domain:   cfg.Host,
		})

		http.SetCookie(w, &http.Cookie{
			Name:     "state",
			Value:    state,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Domain:   cfg.Host,
		})
		http.Redirect(w, r, "/", http.StatusFound)
	}))
}

func JWKSHandler(cfg Config) http.Handler {
	return corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		publicJWK, err := key.PrivateJWKtoPublicJWK(cfg.SecretJWK)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys":[`))
		w.Write([]byte(publicJWK))
		w.Write([]byte(`]}`))
	}))
}

func ClientMetadataHandler(cfg Config) http.Handler {
	return corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		clientMetadata := getClientMetadata(cfg.Protocol, path.Join(cfg.Host, cfg.EndpointPath))
		clientMetadataJSON, err := json.Marshal(clientMetadata)
		if err != nil {
			http.Error(w, "Not Found", http.StatusNotFound)
		}
		w.Write(clientMetadataJSON)
	}))
}

func LogoutHandler(cfg Config, persister Persister) http.Handler {
	return corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		persister.DeleteSession(r.URL.Query().Get("state"))

		// Unset all the cookies we previously set
		http.SetCookie(w, &http.Cookie{
			Name:     "did",
			Value:    "",
			Path:     "/",
			Secure:   true,
			HttpOnly: false,
			SameSite: http.SameSiteLaxMode,
			Domain:   cfg.Host,
			MaxAge:   -1,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "handle",
			Value:    "",
			Path:     "/",
			Secure:   true,
			HttpOnly: false,
			SameSite: http.SameSiteLaxMode,
			Domain:   cfg.Host,
			MaxAge:   -1,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "pds_url",
			Value:    "",
			Path:     "/",
			Secure:   true,
			HttpOnly: false,
			SameSite: http.SameSiteLaxMode,
			Domain:   cfg.Host,
			MaxAge:   -1,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "state",
			Value:    "",
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Domain:   cfg.Host,
			MaxAge:   -1,
		})

		http.Redirect(w, r, "/", http.StatusFound)
	}))
}
