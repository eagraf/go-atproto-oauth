package oauth

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
)

// ATProto specific OAuth logic goes here

func isValidDID(did string) bool {
	// Basic DID validation - checks if it starts with "did:"
	return strings.HasPrefix(did, "did:")
}

func isValidHandle(domain string) bool {
	// Basic domain validation - only allows simple hostnames
	match, _ := regexp.MatchString(`^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9](\.[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])*$`, domain)
	return match
}

func getUserHandle(handle string) (string, error) {
	txtRecords, err := net.LookupTXT(fmt.Sprintf("_atproto.%s", handle))
	if err != nil {
		return "", fmt.Errorf("DNS lookup failed: %v", err)
	}

	for _, record := range txtRecords {
		if strings.HasPrefix(record, "did=") {
			did := strings.TrimPrefix(record, "did=")
			if isValidDID(did) {
				return did, nil
			}
		}
	}

	return "", fmt.Errorf("no valid DID found for handle: %s", handle)
}

func getDID(did string) (map[string]interface{}, error) {
	if strings.HasPrefix(did, "did:plc:") {
		// Handle did:plc resolution
		resp, err := http.Get(fmt.Sprintf("https://plc.directory/%s", did))
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to resolve DID: %s, status: %d", did, resp.StatusCode)
		}

		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, err
		}
		return result, nil

	} else if strings.HasPrefix(did, "did:web:") {
		// Handle did:web resolution
		domain := did[8:] // Remove "did:web:" prefix
		if !isValidHandle(domain) {
			return nil, fmt.Errorf("invalid domain in did:web: %s", domain)
		}

		resp, err := http.Get(fmt.Sprintf("https://%s/.well-known/did.json", domain))
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to resolve DID: %s, status: %d", did, resp.StatusCode)
		}

		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, err
		}
		return result, nil
	}

	return nil, fmt.Errorf("unsupported DID type: %s", did)
}

func getPDSURL(handle string, cfg Config) (string, error) {
	if cfg.PDSURL != "" {
		return cfg.PDSURL, nil
	}

	// Resolve handle -> did
	did, err := getUserHandle(handle)
	if err != nil {
		return "", fmt.Errorf("failed to resolve DID: %v", err)
	}

	// Resolve the DID document
	didDoc, err := getDID(did)
	if err != nil {
		return "", fmt.Errorf("failed to resolve DID document: %v", err)
	}

	// Extract service endpoint from DID document
	services, ok := didDoc["service"].([]interface{})
	if !ok {
		return "", fmt.Errorf("invalid or missing service in DID document")
	}

	for _, service := range services {
		svc, ok := service.(map[string]interface{})
		if !ok {
			continue
		}

		// Look for the atproto PDS service
		if svc["type"] == "AtprotoPersonalDataServer" {
			if endpoint, ok := svc["serviceEndpoint"].(string); ok {
				return endpoint, nil
			}
		}
	}

	return "", fmt.Errorf("no PDS endpoint found in DID document")
}
