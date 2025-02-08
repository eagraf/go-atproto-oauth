package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func resolvePDSAuthServer(url string) (string, error) {
	path := "/.well-known/oauth-protected-resource"
	resp, err := http.Get(url + path)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	authServers, ok := result["authorization_servers"].([]interface{})
	if !ok {
		return "", fmt.Errorf("invalid or missing authorization_servers in PDS metadata")
	}
	authServer, ok := authServers[0].(string)
	if !ok {
		return "", fmt.Errorf("invalid or missing authorization_servers[0] in PDS metadata")
	}

	return authServer, nil
}

// fetchAuthServerMeta does an HTTP GET for Authorization Server (entryway) metadata, verify the contents, and return the metadata as a dict
func fetchAuthServerMeta(url string) (map[string]interface{}, error) {
	// TODO assert URL is safe
	// TODO use a hardened HTTP client

	path := "/.well-known/oauth-authorization-server"
	resp, err := http.Get(url + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	// TODO do some validation on the metadata

	return result, nil
}
