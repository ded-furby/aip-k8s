package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/onsi/gomega"
	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/agent-control-plane/aip-k8s/api/v1alpha1"
)

func runSessionTokenTests(t *testing.T, directClient client.Client, watchClient client.WithWatch, ctx context.Context) {
	// Clean up left-overs before starting session token tests.
	// Best-effort cleanup: these may fail if the namespace is empty or the
	// controller hasn't finished reconciling — not fatal to the test suite.
	_ = directClient.DeleteAllOf(ctx, &v1alpha1.AgentRequest{}, client.InNamespace("default"))
	_ = directClient.DeleteAllOf(ctx, &coordinationv1.Lease{}, client.InNamespace("default"))

	t.Run("AIP discovery endpoint", func(t *testing.T) {
		gm := gomega.NewWithT(t)
		s := &Server{
			externalURL:    "https://gw.example",
			oidcIssuerURL:  "https://idp.example",
			oidcClientID:   "aip-public",
			deviceEndpoint: "https://idp.example/device",
		}
		req := httptest.NewRequest("GET", "/.well-known/aip", nil)
		rr := httptest.NewRecorder()
		s.handleAIPDiscovery(rr, req)
		gm.Expect(rr.Code).To(gomega.Equal(http.StatusOK))
		var doc map[string]any
		gm.Expect(json.Unmarshal(rr.Body.Bytes(), &doc)).To(gomega.Succeed())
		gm.Expect(doc["gateway"]).To(gomega.Equal("https://gw.example"))
		gm.Expect(doc["oidc_issuer"]).To(gomega.Equal("https://idp.example"))
		gm.Expect(doc["oidc_client_id"]).To(gomega.Equal("aip-public"))
		gm.Expect(doc["device_authorization_endpoint"]).To(gomega.Equal("https://idp.example/device"))
	})

	t.Run("Session token — missing service → 400", func(t *testing.T) {
		gm := gomega.NewWithT(t)
		body, _ := json.Marshal(sessionTokenRequest{})
		req := httptest.NewRequest("POST", "/agent-registrations/test/token", bytes.NewBuffer(body))
		req.SetPathValue("name", "test")
		reqCtx := withCallerSub(context.Background(), "some-agent")
		reqCtx = withCallerGroups(reqCtx, []string{})
		req = req.WithContext(reqCtx)
		rr := httptest.NewRecorder()
		s := &Server{
			client:       directClient,
			apiReader:    directClient,
			roles:        newRoleConfig("some-agent", "", "", "", "", ""),
			authRequired: true,
		}
		s.handleSessionToken(rr, req)
		gm.Expect(rr.Code).To(gomega.Equal(http.StatusBadRequest))
		gm.Expect(rr.Body.String()).To(gomega.ContainSubstring("service is required"))
	})

	t.Run("Session token — unauthorized caller → 403", func(t *testing.T) {
		gm := gomega.NewWithT(t)
		reg := &v1alpha1.AgentRegistration{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "unauth-test-reg",
				Namespace: "default",
			},
			Spec: v1alpha1.AgentRegistrationSpec{
				AgentIdentity: "svc-bot",
			},
		}
		gm.Expect(directClient.Create(ctx, reg)).To(gomega.Succeed())
		defer func() { _ = directClient.Delete(ctx, reg) }()
		patchBase := reg.DeepCopy()
		reg.Status.Phase = v1alpha1.PhaseApproved
		reg.Status.RegisteredBy = "owner@example"
		gm.Expect(directClient.Status().Patch(ctx, reg, client.MergeFrom(patchBase))).To(gomega.Succeed())

		body, _ := json.Marshal(sessionTokenRequest{Service: "k8s"})
		req := httptest.NewRequest("POST", "/agent-registrations/unauth-test-reg/token", bytes.NewBuffer(body))
		req.SetPathValue("name", "unauth-test-reg")
		reqCtx := withCallerSub(context.Background(), "stranger")
		reqCtx = withCallerGroups(reqCtx, []string{})
		req = req.WithContext(reqCtx)
		rr := httptest.NewRecorder()
		s := &Server{
			client:       directClient,
			apiReader:    directClient,
			regCache:     newRegistrationCache(directClient),
			roles:        newRoleConfig("stranger,svc-bot,owner@example", "", "", "", "", ""),
			authRequired: true,
		}
		s.handleSessionToken(rr, req)
		gm.Expect(rr.Code).To(gomega.Equal(http.StatusForbidden))
	})

	t.Run("Session token — no-wait mode → 202 with agentRequestName", func(t *testing.T) {
		gm := gomega.NewWithT(t)
		reg := &v1alpha1.AgentRegistration{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nowait-test-reg",
				Namespace: "default",
			},
			Spec: v1alpha1.AgentRegistrationSpec{
				AgentIdentity: "agent-1",
			},
		}
		gm.Expect(directClient.Create(ctx, reg)).To(gomega.Succeed())
		defer func() {
			// Best-effort cleanup in defer; failures are non-actionable.
			_ = directClient.Delete(ctx, reg)
			_ = directClient.DeleteAllOf(ctx, &v1alpha1.AgentRequest{}, client.InNamespace("default"))
			_ = directClient.DeleteAllOf(ctx, &coordinationv1.Lease{}, client.InNamespace("default"))
		}()
		patchBase := reg.DeepCopy()
		reg.Status.Phase = v1alpha1.PhaseApproved
		gm.Expect(directClient.Status().Patch(ctx, reg, client.MergeFrom(patchBase))).To(gomega.Succeed())
		body, _ := json.Marshal(sessionTokenRequest{Service: "k8s"})
		req := httptest.NewRequest("POST", "/agent-registrations/nowait-test-reg/token?no-wait=true", bytes.NewBuffer(body))
		req.SetPathValue("name", "nowait-test-reg")
		reqCtx := withCallerSub(context.Background(), "agent-1")
		reqCtx = withCallerGroups(reqCtx, []string{})
		req = req.WithContext(reqCtx)
		rr := httptest.NewRecorder()
		s := &Server{
			client:       directClient,
			apiReader:    directClient,
			regCache:     setupTestRegCache(),
			roles:        newRoleConfig("agent-1", "", "", "", "", ""),
			authRequired: true,
		}
		s.handleSessionToken(rr, req)
		gm.Expect(rr.Code).To(gomega.Equal(http.StatusAccepted))
		var resp map[string]any
		gm.Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(gomega.Succeed())
		gm.Expect(resp["agentRequestName"]).ToNot(gomega.BeNil())
	})

	t.Run("Session token — full round trip (approved by controller)", func(t *testing.T) {
		gm := gomega.NewWithT(t)
		reg := &v1alpha1.AgentRegistration{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "roundtrip-test-reg",
				Namespace: "default",
			},
			Spec: v1alpha1.AgentRegistrationSpec{
				AgentIdentity: "agent-1",
			},
		}
		gm.Expect(directClient.Create(ctx, reg)).To(gomega.Succeed())
		defer func() {
			_ = directClient.Delete(ctx, reg)
			_ = directClient.DeleteAllOf(ctx, &v1alpha1.AgentRequest{}, client.InNamespace("default"))
			_ = directClient.DeleteAllOf(ctx, &coordinationv1.Lease{}, client.InNamespace("default"))
		}()
		// Set status after creation (status is a subresource).
		patchBase := reg.DeepCopy()
		reg.Status.Phase = v1alpha1.PhaseApproved
		gm.Expect(directClient.Status().Patch(ctx, reg, client.MergeFrom(patchBase))).To(gomega.Succeed())

		body, _ := json.Marshal(sessionTokenRequest{
			Service: "k8s",
			TTL:     "1h",
		})
		req := httptest.NewRequest("POST", "/agent-registrations/roundtrip-test-reg/token", bytes.NewBuffer(body))
		req.SetPathValue("name", "roundtrip-test-reg")
		reqCtx := withCallerSub(context.Background(), "agent-1")
		reqCtx = withCallerGroups(reqCtx, []string{})
		req = req.WithContext(reqCtx)
		rr := httptest.NewRecorder()
		s := &Server{
			client:       directClient,
			apiReader:    directClient,
			watchClient:  watchClient,
			regCache:     setupTestRegCache(),
			roles:        newRoleConfig("agent-1", "", "", "", "", ""),
			authRequired: true,
			waitTimeout:  10 * time.Second,
		}

		s.handleSessionToken(rr, req)
		if rr.Code != http.StatusOK {
			var list v1alpha1.AgentRequestList
			_ = directClient.List(ctx, &list, client.InNamespace("default"))
			for _, ar := range list.Items {
				t.Logf("DEBUG AgentRequest Name: %s, Spec: %+v, Status Phase: %s, Conditions: %+v",
					ar.Name, ar.Spec, ar.Status.Phase, ar.Status.Conditions)
			}
		}
		gm.Expect(rr.Code).To(gomega.Equal(http.StatusOK))

		var resp sessionTokenResponse
		gm.Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(gomega.Succeed())
		gm.Expect(resp.Token).To(gomega.Equal("test-token"))
		gm.Expect(resp.ExecCredential).NotTo(gomega.BeNil())
		gm.Expect(resp.ExecCredential.Status.Token).To(gomega.Equal("test-token"))

		// Check the created AgentRequest in the API server
		var list v1alpha1.AgentRequestList
		gm.Expect(directClient.List(ctx, &list, client.InNamespace("default"))).To(gomega.Succeed())
		var found *v1alpha1.AgentRequest
		for i := range list.Items {
			ar := &list.Items[i]
			if ar.Spec.AgentIdentity == "agent-1" && ar.Spec.Action == "session.k8s" {
				found = ar
				break
			}
		}
		gm.Expect(found).NotTo(gomega.BeNil())
		gm.Expect(found.Spec.Parameters).NotTo(gomega.BeNil())
		var params map[string]string
		gm.Expect(json.Unmarshal(found.Spec.Parameters.Raw, &params)).To(gomega.Succeed())
		gm.Expect(params["ttl"]).To(gomega.Equal("1h"))
	})
}
