package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/agent-control-plane/aip-k8s/api/v1alpha1"
)

const maxRequestBodyBytes = 1 << 20 // 1 MiB

type selfRegisterRequest struct {
	RequestedServices []string                       `json:"requestedServices,omitempty"`
	Mode              v1alpha1.AgentRegistrationMode `json:"mode,omitempty"`
}

// handleCreateAgentRegistration creates a new AgentRegistration.
func (s *Server) handleCreateAgentRegistration(w http.ResponseWriter, r *http.Request) {
	sub := callerSubFromCtx(r.Context())
	groups := callerGroupsFromCtx(r.Context())
	if !requireRole(s.roles, roleAdmin, sub, groups, w) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	ns := r.URL.Query().Get("namespace")
	if ns == "" {
		ns = defaultNamespace
	}

	var reg v1alpha1.AgentRegistration
	if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if reg.Spec.AgentIdentity == "" {
		writeError(w, http.StatusBadRequest, "agentIdentity is required")
		return
	}

	reg.Namespace = ns

	if err := s.client.Create(r.Context(), &reg); err != nil {
		if apierrors.IsAlreadyExists(err) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		if apierrors.IsInvalid(err) || apierrors.IsBadRequest(err) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, reg)
}

// handleListAgentRegistrations lists AgentRegistrations.
func (s *Server) handleListAgentRegistrations(w http.ResponseWriter, r *http.Request) {
	sub := callerSubFromCtx(r.Context())
	groups := callerGroupsFromCtx(r.Context())
	if s.authRequired && sub == "" {
		writeError(w, http.StatusUnauthorized, "caller identity required")
		return
	}

	if !requireAnyRole(s.roles, []string{roleAdmin, roleReviewer}, sub, groups, w) {
		return
	}

	ns := r.URL.Query().Get("namespace")
	if ns == "" {
		ns = defaultNamespace
	}

	var list v1alpha1.AgentRegistrationList
	if err := s.client.List(r.Context(), &list, client.InNamespace(ns)); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, list)
}

// handleGetAgentRegistration gets a single AgentRegistration by name.
func (s *Server) handleGetAgentRegistration(w http.ResponseWriter, r *http.Request) {
	sub := callerSubFromCtx(r.Context())
	groups := callerGroupsFromCtx(r.Context())
	if s.authRequired && sub == "" {
		writeError(w, http.StatusUnauthorized, "caller identity required")
		return
	}

	if !requireAnyRole(s.roles, []string{roleAdmin, roleReviewer}, sub, groups, w) {
		return
	}

	ns := r.URL.Query().Get("namespace")
	if ns == "" {
		ns = defaultNamespace
	}
	name := r.PathValue("name")

	var reg v1alpha1.AgentRegistration
	if err := s.client.Get(r.Context(), types.NamespacedName{Name: name, Namespace: ns}, &reg); err != nil {
		if apierrors.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, reg)
}

// handleReplaceAgentRegistration updates/replaces an existing AgentRegistration.
func (s *Server) handleReplaceAgentRegistration(w http.ResponseWriter, r *http.Request) {
	sub := callerSubFromCtx(r.Context())
	groups := callerGroupsFromCtx(r.Context())
	if !requireRole(s.roles, roleAdmin, sub, groups, w) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	ns := r.URL.Query().Get("namespace")
	if ns == "" {
		ns = defaultNamespace
	}
	name := r.PathValue("name")

	var newReg v1alpha1.AgentRegistration
	if err := json.NewDecoder(r.Body).Decode(&newReg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if newReg.Name != "" && newReg.Name != name {
		writeError(w, http.StatusBadRequest, "name in body must match name in path")
		return
	}

	if newReg.Spec.AgentIdentity == "" {
		writeError(w, http.StatusBadRequest, "agentIdentity is required")
		return
	}

	var updated v1alpha1.AgentRegistration
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := s.client.Get(r.Context(), types.NamespacedName{Name: name, Namespace: ns}, &updated); err != nil {
			return err
		}
		updated.Spec = newReg.Spec
		updated.Labels = newReg.Labels
		updated.Annotations = newReg.Annotations
		return s.client.Update(r.Context(), &updated)
	})

	if err != nil {
		if apierrors.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, updated)
}

// handleDeleteAgentRegistration deletes an AgentRegistration.
func (s *Server) handleDeleteAgentRegistration(w http.ResponseWriter, r *http.Request) {
	groups := callerGroupsFromCtx(r.Context())
	sub := callerSubFromCtx(r.Context())
	if !requireRole(s.roles, roleAdmin, sub, groups, w) {
		return
	}

	name := r.PathValue("name")
	namespaceQuery := r.URL.Query().Get("namespace")
	if namespaceQuery == "" {
		namespaceQuery = defaultNamespace
	}

	regToDelete := &v1alpha1.AgentRegistration{}
	regToDelete.Name = name
	regToDelete.Namespace = namespaceQuery

	delErr := s.client.Delete(r.Context(), regToDelete)
	if delErr != nil {
		if apierrors.IsNotFound(delErr) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, delErr.Error())
		return
	}

	var checkedReg v1alpha1.AgentRegistration
	key := types.NamespacedName{Namespace: namespaceQuery, Name: name}
	getErr := s.apiReader.Get(r.Context(), key, &checkedReg)
	if getErr != nil {
		if apierrors.IsNotFound(getErr) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeError(w, http.StatusInternalServerError, getErr.Error())
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// handleSelfRegisterAgentRegistration allows an authenticated agent to register itself.
// The agent's identity, issuer, and namespace are derived from the authenticated request,
// not from the request body. Only requestedServices and mode may be provided in the body.
func (s *Server) handleSelfRegisterAgentRegistration(w http.ResponseWriter, r *http.Request) {
	sub := callerSubFromCtx(r.Context())
	issuer := callerIssuerFromCtx(r.Context())

	if s.authRequired && sub == "" {
		writeError(w, http.StatusUnauthorized, "caller identity required")
		return
	}

	if issuer == "" {
		writeError(w, http.StatusBadRequest, "OIDC issuer required for self-registration")
		return
	}

	groups := callerGroupsFromCtx(r.Context())
	if !requireRole(s.roles, roleAgent, sub, groups, w) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	var body selfRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ns := defaultNamespace
	if s.regCache != nil && s.regCache.namespace != "" {
		ns = s.regCache.namespace
	}

	mode := body.Mode
	if mode == "" {
		mode = v1alpha1.AgentRegistrationModeStanding
	}

	if sub == "" {
		writeError(w, http.StatusBadRequest, "agent identity not available")
		return
	}

	reg := &v1alpha1.AgentRegistration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      v1alpha1.RegistrationObjectName(sub),
			Namespace: ns,
		},
		Spec: v1alpha1.AgentRegistrationSpec{
			AgentIdentity:     sub,
			Mode:              mode,
			RequestedServices: body.RequestedServices,
			OIDC: &v1alpha1.AgentRegistrationOIDC{
				Issuer: issuer,
			},
		},
	}

	if err := s.client.Create(r.Context(), reg); err != nil {
		if apierrors.IsAlreadyExists(err) {
			writeError(w, http.StatusConflict, fmt.Sprintf("agent %q is already registered", sub))
			return
		}
		if apierrors.IsInvalid(err) || apierrors.IsBadRequest(err) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		log.Printf("ERROR: failed to self-register AgentRegistration name=%s namespace=%s agent=%s err=%v",
			reg.Name, ns, sub, err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Populate status.registeredBy: status is a subresource and cannot be set
	// on Create, so patch it immediately after creation.
	patchBase := reg.DeepCopy()
	reg.Status.RegisteredBy = sub
	if patchErr := s.client.Status().Patch(r.Context(), reg, client.MergeFrom(patchBase)); patchErr != nil {
		log.Printf("WARNING: failed to set status.registeredBy for AgentRegistration name=%s namespace=%s agent=%s err=%v",
			reg.Name, ns, sub, patchErr)
		// Re-fetch so the returned object reflects actual stored state.
		if getErr := s.client.Get(r.Context(), types.NamespacedName{Name: reg.Name, Namespace: ns}, reg); getErr != nil {
			log.Printf("ERROR: failed to re-fetch AgentRegistration after status patch failure name=%s namespace=%s err=%v",
				reg.Name, ns, getErr)
		}
	}

	// Auto-approve when registration policy is auto.
	if s.registrationPolicy == policyAuto {
		now := metav1.Now()
		patchBase2 := reg.DeepCopy()
		reg.Status.Phase = v1alpha1.PhaseApproved
		reg.Status.ApprovedServices = reg.Spec.RequestedServices
		reg.Status.ApprovedAt = &now
		if patchErr := s.client.Status().Patch(r.Context(), reg,
			client.MergeFromWithOptions(patchBase2, client.MergeFromWithOptimisticLock{})); patchErr != nil {
			log.Printf("Auto-approve patch failed for AgentRegistration name=%s err=%v", reg.Name, patchErr)
			if getErr := s.client.Get(r.Context(), types.NamespacedName{Name: reg.Name, Namespace: ns}, reg); getErr != nil {
				log.Printf("Re-fetch after auto-approve failure for AgentRegistration name=%s err=%v", reg.Name, getErr)
			}
		}
	}

	writeJSON(w, http.StatusCreated, reg)
}

type approveRegistrationBody struct {
	ApprovedServices []string `json:"approvedServices,omitempty"`
	Reason           string   `json:"reason,omitempty"`
}

type denyRegistrationBody struct {
	Reason string `json:"reason,omitempty"`
}

// handleApproveAgentRegistration transitions a registration's status.phase to Approved.
func (s *Server) handleApproveAgentRegistration(w http.ResponseWriter, r *http.Request) {
	sub := callerSubFromCtx(r.Context())
	groups := callerGroupsFromCtx(r.Context())
	if !requireRole(s.roles, roleReviewer, sub, groups, w) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	var body approveRegistrationBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	name := r.PathValue("name")
	ns := r.URL.Query().Get("namespace")
	if ns == "" {
		ns = defaultNamespace
	}

	// Pre-check with apiReader for immediate 404 without retry overhead.
	var preCheck v1alpha1.AgentRegistration
	if err := s.apiReader.Get(r.Context(), types.NamespacedName{Name: name, Namespace: ns}, &preCheck); err != nil {
		if apierrors.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var reg v1alpha1.AgentRegistration
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// Use apiReader (uncached) inside the retry loop so even if the informer
		// cache hasn't observed the object yet, the direct read succeeds.
		if err := s.apiReader.Get(r.Context(), types.NamespacedName{Name: name, Namespace: ns}, &reg); err != nil {
			return err
		}
		if reg.Status.Phase == v1alpha1.PhaseApproved || reg.Status.Phase == v1alpha1.PhaseDenied {
			return errAlreadyTerminal
		}
		// Self-approval guard: reviewer cannot approve their own registration.
		if s.authRequired && (reg.Spec.AgentIdentity == sub || reg.Status.RegisteredBy == sub) {
			return errSelfApproval
		}
		now := metav1.Now()
		base := reg.DeepCopy()
		reg.Status.Phase = v1alpha1.PhaseApproved
		if len(body.ApprovedServices) > 0 {
			// Validate: approvedServices must be a subset of requestedServices.
			if !isSubset(body.ApprovedServices, reg.Spec.RequestedServices) {
				return fmt.Errorf("approvedServices %q are not a subset of requestedServices %q: %w",
					body.ApprovedServices, reg.Spec.RequestedServices, errValidation)
			}
			reg.Status.ApprovedServices = body.ApprovedServices
		} else {
			reg.Status.ApprovedServices = reg.Spec.RequestedServices
		}
		reg.Status.ApprovedAt = &now
		if body.Reason != "" {
			log.Printf("Approved AgentRegistration name=%s namespace=%s reason=%q", name, ns, body.Reason)
		}
		return s.client.Status().Patch(r.Context(), &reg,
			client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
	}); err != nil {
		if apierrors.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		if errors.Is(err, errAlreadyTerminal) {
			writeError(w, http.StatusConflict, fmt.Sprintf("registration is already in phase %q", reg.Status.Phase))
			return
		}
		if errors.Is(err, errSelfApproval) {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		if errors.Is(err, errValidation) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, reg)
}

func isSubset(sub, super []string) bool {
	superSet := make(map[string]struct{}, len(super))
	for _, s := range super {
		superSet[s] = struct{}{}
	}
	for _, s := range sub {
		if _, ok := superSet[s]; !ok {
			return false
		}
	}
	return true
}

// handleDenyAgentRegistration transitions a registration's status.phase to Denied.
func (s *Server) handleDenyAgentRegistration(w http.ResponseWriter, r *http.Request) {
	sub := callerSubFromCtx(r.Context())
	groups := callerGroupsFromCtx(r.Context())
	if !requireRole(s.roles, roleReviewer, sub, groups, w) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	var body denyRegistrationBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	name := r.PathValue("name")
	ns := r.URL.Query().Get("namespace")
	if ns == "" {
		ns = defaultNamespace
	}

	// Pre-check with apiReader for immediate 404 without retry overhead.
	var preCheck v1alpha1.AgentRegistration
	if err := s.apiReader.Get(r.Context(), types.NamespacedName{Name: name, Namespace: ns}, &preCheck); err != nil {
		if apierrors.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var reg v1alpha1.AgentRegistration
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := s.apiReader.Get(r.Context(), types.NamespacedName{Name: name, Namespace: ns}, &reg); err != nil {
			return err
		}
		if reg.Status.Phase == v1alpha1.PhaseApproved || reg.Status.Phase == v1alpha1.PhaseDenied {
			return errAlreadyTerminal
		}
		base := reg.DeepCopy()
		reg.Status.Phase = v1alpha1.PhaseDenied
		if body.Reason != "" {
			log.Printf("Denied AgentRegistration name=%s namespace=%s reason=%q", name, ns, body.Reason)
			meta.SetStatusCondition(&reg.Status.Conditions, metav1.Condition{
				Type:    "Denied",
				Status:  metav1.ConditionTrue,
				Reason:  "DeniedByReviewer",
				Message: body.Reason,
			})
		}
		return s.client.Status().Patch(r.Context(), &reg,
			client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
	}); err != nil {
		if apierrors.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		if errors.Is(err, errAlreadyTerminal) {
			writeError(w, http.StatusConflict, fmt.Sprintf("registration is already in phase %q", reg.Status.Phase))
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, reg)
}
