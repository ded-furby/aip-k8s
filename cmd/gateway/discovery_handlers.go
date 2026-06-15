package main

import (
	"net/http"
)

func (s *Server) handleAIPDiscovery(w http.ResponseWriter, r *http.Request) {
	if s.externalURL == "" {
		writeError(w, http.StatusInternalServerError, "server externalURL not configured")
		return
	}
	doc := map[string]any{
		"gateway": s.externalURL,
	}
	if s.oidcIssuerURL != "" {
		doc["oidc_issuer"] = s.oidcIssuerURL
	}
	if s.oidcClientID != "" {
		doc["oidc_client_id"] = s.oidcClientID
	}
	if s.deviceEndpoint != "" {
		doc["device_authorization_endpoint"] = s.deviceEndpoint
	}
	writeJSON(w, http.StatusOK, doc)
}
