package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"slices"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/agent-control-plane/aip-k8s/api/v1alpha1"
)

func agentRegistrationPayload(reg *v1alpha1.AgentRegistration) map[string]any {
	return map[string]any{
		"name":             reg.Name,
		"agentIdentity":    reg.Spec.AgentIdentity,
		"phase":            reg.Status.Phase,
		"approvedServices": reg.Status.ApprovedServices,
		"approvedAt":       reg.Status.ApprovedAt,
		"conditions":       reg.Status.Conditions,
	}
}

func isTerminalRegistrationPhase(reg *v1alpha1.AgentRegistration) bool {
	return reg.Status.Phase == v1alpha1.PhaseApproved || reg.Status.Phase == v1alpha1.PhaseDenied
}

func (s *Server) streamAgentRegistrationPhase(
	w http.ResponseWriter, r *http.Request,
	reg *v1alpha1.AgentRegistration, ns string,
) {
	rc := http.NewResponseController(w)

	writeSSEHeaders(w)
	if err := rc.Flush(); err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.waitTimeout)
	defer cancel()

	if isTerminalRegistrationPhase(reg) {
		if err := writeSSEEvent(w, rc, sseEventResult, agentRegistrationPayload(reg)); err != nil {
			log.Printf("SSE: failed to write terminal result for registration %s: %v", reg.Name, err)
		}
		return
	}

	// Re-read with apiReader before setting up the watch. This closes the race
	// between the caller's apiReader.Get and this Watch setup: any phase transition
	// that fired in that window will be visible here, preventing a hung SSE stream.
	var current v1alpha1.AgentRegistration
	if err := s.apiReader.Get(ctx, client.ObjectKey{Namespace: ns, Name: reg.Name}, &current); err != nil {
		log.Printf("SSE: failed to re-read AgentRegistration name=%s namespace=%s err=%v", reg.Name, ns, err)
		writeSSEError(w, rc, "failed to re-read AgentRegistration")
		return
	}
	if isTerminalRegistrationPhase(&current) {
		if err := writeSSEEvent(w, rc, sseEventResult, agentRegistrationPayload(&current)); err != nil {
			log.Printf("SSE: failed to write terminal result for registration %s: %v", current.Name, err)
		}
		return
	}
	if current.Status.Phase != "" {
		if err := writeSSEEvent(w, rc, sseEventUpdate, agentRegistrationPayload(&current)); err != nil {
			return
		}
	}

	watcher, err := s.watchClient.Watch(ctx, &v1alpha1.AgentRegistrationList{},
		client.InNamespace(ns),
		client.MatchingFields{"metadata.name": current.Name},
		&client.ListOptions{Raw: &metav1.ListOptions{ResourceVersion: current.ResourceVersion}},
	)
	if err != nil {
		log.Printf("SSE: failed to watch AgentRegistration name=%s namespace=%s err=%v", reg.Name, ns, err)
		writeSSEError(w, rc, "failed to watch AgentRegistration")
		return
	}
	defer watcher.Stop()

	var lastStatusJSON string
	for {
		select {
		case <-ctx.Done():
			if r.Context().Err() == nil {
				writeSSEError(w, rc, "timed out waiting for AgentRegistration resolution")
			}
			return
		case event, ok := <-watcher.ResultChan():
			if !ok {
				writeSSEError(w, rc, "watch channel closed unexpectedly")
				return
			}
			if event.Type == watch.Error {
				writeSSEError(w, rc, "watch error from API server")
				return
			}
			if event.Type == watch.Deleted {
				writeSSEError(w, rc, "AgentRegistration was deleted")
				return
			}
			if event.Type != watch.Added && event.Type != watch.Modified {
				continue
			}

			updated, ok := event.Object.(*v1alpha1.AgentRegistration)
			if !ok {
				continue
			}
			if updated.Name != reg.Name {
				continue
			}

			if isTerminalRegistrationPhase(updated) {
				if err := writeSSEEvent(w, rc, sseEventResult, agentRegistrationPayload(updated)); err != nil {
					log.Printf("SSE: failed to write terminal result for registration %s: %v", reg.Name, err)
				}
				return
			}

			statusJSON, err := json.Marshal(updated.Status)
			if err != nil {
				log.Printf("SSE: failed to marshal status for registration %s: %v", reg.Name, err)
			} else if string(statusJSON) == lastStatusJSON {
				continue
			} else {
				lastStatusJSON = string(statusJSON)
			}

			if err := writeSSEEvent(w, rc, sseEventUpdate, agentRegistrationPayload(updated)); err != nil {
				return
			}
		}
	}
}

func (s *Server) handleWatchAgentRegistration(w http.ResponseWriter, r *http.Request) {
	sub := callerSubFromCtx(r.Context())
	groups := callerGroupsFromCtx(r.Context())
	if s.authRequired && sub == "" {
		writeError(w, http.StatusUnauthorized, "caller identity required")
		return
	}
	if !acceptsSSE(r) {
		writeError(w, http.StatusBadRequest, "Accept header must include text/event-stream")
		return
	}
	name := r.PathValue("name")
	ns := r.URL.Query().Get("namespace")
	if ns == "" {
		ns = defaultNamespace
	}

	var reg v1alpha1.AgentRegistration
	// Use apiReader (uncached) to avoid the create-then-watch race: if the
	// registration was just created and the informer cache has not yet observed
	// the new object, a cached read returns 404. The uncached read guarantees
	// the just-created object is visible. Same pattern as streamAgentRequestPhase.
	if err := s.apiReader.Get(r.Context(), client.ObjectKey{Namespace: ns, Name: name}, &reg); err != nil {
		if apierrors.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		log.Printf("SSE: failed to read AgentRegistration name=%s namespace=%s err=%v", name, ns, err)
		writeError(w, http.StatusInternalServerError, "failed to read AgentRegistration")
		return
	}

	// Authorization: agents may only watch their own registration.
	isPlainAgent := s.authRequired && s.roles.isAgent(sub, groups) &&
		!s.roles.isReviewer(sub, groups) && !s.roles.isAdmin(sub, groups)
	if isPlainAgent {
		ownedByAgent := reg.Spec.AgentIdentity == sub
		if !ownedByAgent && reg.Spec.OIDC != nil {
			ownedByAgent = slices.Contains(reg.Spec.OIDC.AllowedSubjects, sub)
		}
		// Fallback: check if the regCache links the agent's sub to this registration.
		if !ownedByAgent && s.regCache != nil {
			match := s.regCache.getForSubject("", sub)
			ownedByAgent = match != nil && match.Name == reg.Name && match.Namespace == ns
		}
		if !ownedByAgent {
			writeError(w, http.StatusForbidden, "agents may only watch their own registration")
			return
		}
	} else if s.authRequired && !s.roles.isReviewer(sub, groups) && !s.roles.isAdmin(sub, groups) {
		writeError(w, http.StatusForbidden, "reviewer or admin role required")
		return
	}

	s.streamAgentRegistrationPhase(w, r, &reg, ns)
}
