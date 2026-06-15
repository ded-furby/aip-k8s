package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/agent-control-plane/aip-k8s/api/v1alpha1"
)

type sessionTokenRequest struct {
	Service   string `json:"service"` // required: which MCPServer to exchange for (e.g. "k8s")
	TTL       string `json:"ttl,omitempty"`
	TargetURI string `json:"targetURI,omitempty"`
}

type sessionTokenResponse struct {
	Token          string                 `json:"token"`
	ExecCredential *execCredentialWrapper `json:"execCredential,omitempty"`
}

type execCredentialWrapper struct {
	APIVersion string               `json:"apiVersion"`
	Kind       string               `json:"kind"`
	Status     execCredentialStatus `json:"status"`
}

type execCredentialStatus struct {
	Token               string `json:"token"`
	ExpirationTimestamp string `json:"expirationTimestamp,omitempty"`
}

func (s *Server) handleSessionToken(w http.ResponseWriter, r *http.Request) {
	sub := callerSubFromCtx(r.Context())
	groups := callerGroupsFromCtx(r.Context())

	if s.authRequired && sub == "" {
		writeError(w, http.StatusUnauthorized, "caller identity required")
		return
	}
	if !requireRole(s.roles, roleAgent, sub, groups, w) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var body sessionTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Service == "" {
		writeError(w, http.StatusBadRequest, "service is required")
		return
	}

	name := r.PathValue("name")
	ns := r.URL.Query().Get("namespace")
	if ns == "" {
		ns = defaultNamespace
		if s.regCache != nil && s.regCache.namespace != "" {
			ns = s.regCache.namespace
		}
	}

	var reg v1alpha1.AgentRegistration
	if err := s.apiReader.Get(r.Context(), client.ObjectKey{Namespace: ns, Name: name}, &reg); err != nil {
		if apierrors.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "AgentRegistration not found")
			return
		}
		if apierrors.IsBadRequest(err) || apierrors.IsInvalid(err) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		log.Printf("Session token: failed to read AgentRegistration name=%s namespace=%s err=%v", name, ns, err)
		writeError(w, http.StatusInternalServerError, "failed to read AgentRegistration")
		return
	}

	// Authorization: caller must be authorized to act for this registration.
	// The empty-string guard prevents "" == "" matching in no-auth mode.
	authorized := sub != "" && (sub == reg.Spec.AgentIdentity ||
		sub == reg.Status.RegisteredBy)
	if !authorized && reg.Spec.OIDC != nil {
		authorized = slices.Contains(reg.Spec.OIDC.AllowedSubjects, sub)
	}
	if !authorized {
		writeError(w, http.StatusForbidden, "caller is not authorized to act on behalf of this registration")
		return
	}

	if reg.Status.Phase != v1alpha1.PhaseApproved {
		writeError(w, http.StatusForbidden,
			fmt.Sprintf("registration is not Approved (phase: %s)", reg.Status.Phase))
		return
	}

	// Provider lookup
	if s.regCache == nil {
		writeError(w, http.StatusInternalServerError, "credential cache not available")
		return
	}
	provider := s.regCache.providerFor(reg.Spec.AgentIdentity, body.Service)
	if provider == nil {
		writeError(w, http.StatusNotFound,
			fmt.Sprintf("no credential binding for service %q", body.Service))
		return
	}

	// Build TTL parameters
	var params map[string]string
	if body.TTL != "" {
		params = map[string]string{"ttl": body.TTL}
	}
	paramsRaw := &apiextensionsv1.JSON{}
	if len(params) > 0 {
		raw, err := json.Marshal(params)
		if err != nil {
			log.Printf("Session token: failed to marshal parameters err=%v", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		paramsRaw = &apiextensionsv1.JSON{Raw: raw}
	}

	targetURI := body.TargetURI
	if targetURI == "" {
		targetURI = "k8s://"
	}

	// Create session AgentRequest
	ar := &v1alpha1.AgentRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "session-" + sanitizeDNSSegment(reg.Spec.AgentIdentity, 40) + "-",
			Namespace:    ns,
		},
		Spec: v1alpha1.AgentRequestSpec{
			AgentIdentity: reg.Spec.AgentIdentity,
			Action:        "session.k8s",
			Reason:        fmt.Sprintf("session token requested by %s", sub),
			Target:        v1alpha1.Target{URI: targetURI},
			Parameters:    paramsRaw,
		},
	}
	if err := s.client.Create(r.Context(), ar); err != nil {
		log.Printf("Session token: failed to create AgentRequest generateName=%s err=%v", ar.GenerateName, err)
		writeError(w, http.StatusInternalServerError, "failed to create AgentRequest")
		return
	}

	// no-wait mode
	noWait := r.URL.Query().Get("no-wait") == annotationValueTrue ||
		r.URL.Query().Get("noWait") == annotationValueTrue
	if noWait {
		writeJSON(w, http.StatusAccepted, map[string]any{
			"agentRequestName": ar.Name,
		})
		return
	}

	// Blocking wait for approval
	approved, statusCode, err := s.waitForSessionApproval(r.Context(), ar)
	if err != nil {
		writeError(w, statusCode, err.Error())
		return
	}

	// Exchange via provider.Token
	rawOIDCToken := rawOIDCTokenFromCtx(r.Context())
	bearerToken, err := provider.Token(r.Context(), rawOIDCToken)
	if err != nil {
		log.Printf("Session token: credential exchange failed for service=%q agent=%q err=%v",
			body.Service, reg.Spec.AgentIdentity, err)
		writeError(w, http.StatusInternalServerError, "credential exchange failed")
		return
	}

	resp := &sessionTokenResponse{
		Token: bearerToken,
		ExecCredential: &execCredentialWrapper{
			APIVersion: "client.authentication.k8s.io/v1",
			Kind:       "ExecCredential",
			Status:     execCredentialStatus{Token: bearerToken},
		},
	}
	_ = approved // approved AgentRequest available for audit if needed
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) waitForSessionApproval(
	ctx context.Context, ar *v1alpha1.AgentRequest,
) (*v1alpha1.AgentRequest, int, error) {
	ctx, cancel := context.WithTimeout(ctx, s.waitTimeout)
	defer cancel()

	// Pre-read with apiReader (uncached) to catch already-terminal state
	// and anchor ResourceVersion, avoiding 410 Gone on compacted RVs.
	var current v1alpha1.AgentRequest
	if err := s.apiReader.Get(ctx, client.ObjectKey{Namespace: ar.Namespace, Name: ar.Name}, &current); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to read AgentRequest")
	}
	switch current.Status.Phase {
	case v1alpha1.PhaseApproved:
		return &current, http.StatusOK, nil
	case v1alpha1.PhaseDenied:
		return nil, http.StatusForbidden, fmt.Errorf("session request was denied")
	}

	watcher, err := s.watchClient.Watch(ctx, &v1alpha1.AgentRequestList{},
		client.InNamespace(ar.Namespace),
		client.MatchingFields{"metadata.name": ar.Name},
		&client.ListOptions{Raw: &metav1.ListOptions{ResourceVersion: current.ResourceVersion}},
	)
	if err != nil {
		log.Printf("Session token: failed to watch AgentRequest name=%s err=%v", ar.Name, err)
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to watch AgentRequest")
	}
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, http.StatusGatewayTimeout, fmt.Errorf("timed out waiting for session approval")
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return nil, http.StatusInternalServerError, fmt.Errorf("watch channel closed")
			}
			if event.Type == watch.Error {
				return nil, http.StatusInternalServerError, fmt.Errorf("watch error from API server")
			}
			if event.Type == watch.Deleted {
				return nil, http.StatusForbidden, fmt.Errorf("AgentRequest was deleted")
			}
			if event.Type != watch.Added && event.Type != watch.Modified {
				continue
			}

			updated, ok := event.Object.(*v1alpha1.AgentRequest)
			if !ok || updated.Name != ar.Name {
				continue
			}

			switch updated.Status.Phase {
			case v1alpha1.PhaseApproved:
				return updated, http.StatusOK, nil
			case v1alpha1.PhaseDenied:
				return nil, http.StatusForbidden, fmt.Errorf("session request was denied")
			}
		}
	}
}
