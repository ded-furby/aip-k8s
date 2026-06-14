package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/agent-control-plane/aip-k8s/api/v1alpha1"
)

func runRegistrationApprovalTests(t *testing.T, directClient client.Client,
	watchClient client.WithWatch, ctx context.Context) {
	t.Run("approve happy path", func(t *testing.T) {
		gm := gomega.NewWithT(t)
		reg := &v1alpha1.AgentRegistration{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "approve-test-1",
				Namespace: testDefaultNS,
			},
			Spec: v1alpha1.AgentRegistrationSpec{
				AgentIdentity:     "approve-agent",
				RequestedServices: []string{"svc1", "svc2"},
			},
		}
		gm.Expect(directClient.Create(ctx, reg)).To(gomega.Succeed())
		defer func() {
			if delErr := directClient.Delete(ctx, reg); delErr != nil {
				t.Logf("failed to delete test registration: %v", delErr)
			}
		}()

		s := &Server{
			client:    directClient,
			apiReader: directClient,
			regCache:  newRegistrationCache(directClient),
			roles:     newRoleConfig("", "reviewer-sub", "", "", "", ""),
		}

		body := approveRegistrationBody{
			ApprovedServices: []string{"svc1"},
		}
		jsonBody, err := json.Marshal(body)
		gm.Expect(err).To(gomega.Succeed())
		req := httptest.NewRequest("POST", "/agent-registrations/approve-test-1/approve", bytes.NewBuffer(jsonBody))
		req.SetPathValue("name", "approve-test-1")
		reqCtx := withCallerSub(context.Background(), "reviewer-sub")
		reqCtx = withCallerGroups(reqCtx, []string{})
		req = req.WithContext(reqCtx)
		rr := httptest.NewRecorder()
		s.handleApproveAgentRegistration(rr, req)
		gm.Expect(rr.Code).To(gomega.Equal(http.StatusOK))

		var updated v1alpha1.AgentRegistration
		gm.Expect(json.Unmarshal(rr.Body.Bytes(), &updated)).To(gomega.Succeed())
		gm.Expect(updated.Status.Phase).To(gomega.Equal("Approved"))
		gm.Expect(updated.Status.ApprovedServices).To(gomega.ConsistOf("svc1"))
		gm.Expect(updated.Status.ApprovedAt).ToNot(gomega.BeNil())
	})

	t.Run("deny happy path", func(t *testing.T) {
		gm := gomega.NewWithT(t)
		reg := &v1alpha1.AgentRegistration{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deny-test-1",
				Namespace: testDefaultNS,
			},
			Spec: v1alpha1.AgentRegistrationSpec{
				AgentIdentity: "deny-agent",
			},
		}
		gm.Expect(directClient.Create(ctx, reg)).To(gomega.Succeed())
		defer func() {
			if delErr := directClient.Delete(ctx, reg); delErr != nil {
				t.Logf("failed to delete test registration: %v", delErr)
			}
		}()

		s := &Server{
			client:    directClient,
			apiReader: directClient,
			regCache:  newRegistrationCache(directClient),
			roles:     newRoleConfig("", "reviewer-sub", "", "", "", ""),
		}

		body := denyRegistrationBody{Reason: "not needed"}
		jsonBody, err := json.Marshal(body)
		gm.Expect(err).To(gomega.Succeed())
		req := httptest.NewRequest("POST", "/agent-registrations/deny-test-1/deny", bytes.NewBuffer(jsonBody))
		req.SetPathValue("name", "deny-test-1")
		reqCtx := withCallerSub(context.Background(), "reviewer-sub")
		reqCtx = withCallerGroups(reqCtx, []string{})
		req = req.WithContext(reqCtx)
		rr := httptest.NewRecorder()
		s.handleDenyAgentRegistration(rr, req)
		gm.Expect(rr.Code).To(gomega.Equal(http.StatusOK))

		var updated v1alpha1.AgentRegistration
		gm.Expect(json.Unmarshal(rr.Body.Bytes(), &updated)).To(gomega.Succeed())
		gm.Expect(updated.Status.Phase).To(gomega.Equal("Denied"))
	})

	t.Run("double-approve -> 409", func(t *testing.T) {
		gm := gomega.NewWithT(t)
		reg := &v1alpha1.AgentRegistration{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "double-approve",
				Namespace: testDefaultNS,
			},
			Spec: v1alpha1.AgentRegistrationSpec{
				AgentIdentity: "double-approve-agent",
			},
		}
		gm.Expect(directClient.Create(ctx, reg)).To(gomega.Succeed())
		defer func() {
			if delErr := directClient.Delete(ctx, reg); delErr != nil {
				t.Logf("failed to delete test registration: %v", delErr)
			}
		}()

		s := &Server{
			client:    directClient,
			apiReader: directClient,
			regCache:  newRegistrationCache(directClient),
			roles:     newRoleConfig("", "reviewer-sub", "", "", "", ""),
		}

		// First approve succeeds
		jsonBody, err := json.Marshal(approveRegistrationBody{})
		gm.Expect(err).To(gomega.Succeed())
		req := httptest.NewRequest("POST", "/agent-registrations/double-approve/approve", bytes.NewBuffer(jsonBody))
		req.SetPathValue("name", "double-approve")
		reqCtx := withCallerSub(context.Background(), "reviewer-sub")
		reqCtx = withCallerGroups(reqCtx, []string{})
		req = req.WithContext(reqCtx)
		rr := httptest.NewRecorder()
		s.handleApproveAgentRegistration(rr, req)
		gm.Expect(rr.Code).To(gomega.Equal(http.StatusOK))

		// Second approve -> 409
		req2 := httptest.NewRequest("POST", "/agent-registrations/double-approve/approve", bytes.NewBuffer(jsonBody))
		req2.SetPathValue("name", "double-approve")
		req2Ctx := withCallerSub(context.Background(), "reviewer-sub")
		req2Ctx = withCallerGroups(req2Ctx, []string{})
		req2 = req2.WithContext(req2Ctx)
		rr2 := httptest.NewRecorder()
		s.handleApproveAgentRegistration(rr2, req2)
		gm.Expect(rr2.Code).To(gomega.Equal(http.StatusConflict))
	})

	t.Run("agent role cannot approve -> 403", func(t *testing.T) {
		gm := gomega.NewWithT(t)
		s := &Server{
			client:    directClient,
			apiReader: directClient,
			regCache:  newRegistrationCache(directClient),
			roles:     newRoleConfig("agent-sub", "", "", "", "", ""),
		}
		jsonBody, err := json.Marshal(approveRegistrationBody{})
		gm.Expect(err).To(gomega.Succeed())
		req := httptest.NewRequest("POST", "/agent-registrations/some-name/approve", bytes.NewBuffer(jsonBody))
		req.SetPathValue("name", "some-name")
		reqCtx := withCallerSub(context.Background(), "agent-sub")
		reqCtx = withCallerGroups(reqCtx, []string{})
		req = req.WithContext(reqCtx)
		rr := httptest.NewRecorder()
		s.handleApproveAgentRegistration(rr, req)
		gm.Expect(rr.Code).To(gomega.Equal(http.StatusForbidden))
	})

	t.Run("SSE watch - approved registration", func(t *testing.T) {
		gm := gomega.NewWithT(t)
		reg := &v1alpha1.AgentRegistration{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "sse-approve-watch",
				Namespace: testDefaultNS,
			},
			Spec: v1alpha1.AgentRegistrationSpec{
				AgentIdentity: "sse-approve-agent",
			},
		}
		gm.Expect(directClient.Create(ctx, reg)).To(gomega.Succeed())
		defer func() {
			if delErr := directClient.Delete(ctx, reg); delErr != nil {
				t.Logf("failed to delete test registration: %v", delErr)
			}
		}()

		gm.Eventually(func() error {
			nn := types.NamespacedName{Name: "sse-approve-watch", Namespace: testDefaultNS}
			return directClient.Get(ctx, nn, &v1alpha1.AgentRegistration{})
		}, eventuallyTimeout, eventuallyInterval).Should(gomega.Succeed())

		s := &Server{
			client:      directClient,
			apiReader:   directClient,
			watchClient: watchClient,
			waitTimeout: serverWaitTimeout,
			roles:       newRoleConfig("", "reviewer-sub", "", "", "", ""),
		}

		watchReq := httptest.NewRequest("GET",
			fmt.Sprintf("/agent-registrations/sse-approve-watch/watch?namespace=%s", testDefaultNS), nil)
		watchReq.Header.Set("Accept", "text/event-stream")
		watchReq.SetPathValue("name", "sse-approve-watch")
		watchReqCtx := withCallerSub(context.Background(), "reviewer-sub")
		watchReqCtx = withCallerGroups(watchReqCtx, []string{})
		watchReq = watchReq.WithContext(watchReqCtx)
		watchRR := httptest.NewRecorder()

		doneCh := make(chan struct{})
		go func() {
			defer close(doneCh)
			s.handleWatchAgentRegistration(watchRR, watchReq)
		}()

		// Approve in parallel
		approveS := &Server{
			client:    directClient,
			apiReader: directClient,
			roles:     newRoleConfig("", "reviewer-sub", "", "", "", ""),
		}
		jsonBody, err := json.Marshal(approveRegistrationBody{})
		gm.Expect(err).To(gomega.Succeed())
		approveReq := httptest.NewRequest("POST", "/agent-registrations/sse-approve-watch/approve", bytes.NewBuffer(jsonBody))
		approveReq.SetPathValue("name", "sse-approve-watch")
		approveCtx := withCallerSub(context.Background(), "reviewer-sub")
		approveCtx = withCallerGroups(approveCtx, []string{})
		approveReq = approveReq.WithContext(approveCtx)
		approveRR := httptest.NewRecorder()
		approveS.handleApproveAgentRegistration(approveRR, approveReq)
		gm.Expect(approveRR.Code).To(gomega.Equal(http.StatusOK))

		gm.Eventually(doneCh, eventuallyLongTimeout).Should(gomega.BeClosed())

		events := parseSSEEvents(t, watchRR.Body.String())
		gm.Expect(events).ToNot(gomega.BeEmpty())

		last := events[len(events)-1]
		gm.Expect(last.Type).To(gomega.Equal("result"))
		gm.Expect(last.Data["phase"]).To(gomega.Equal("Approved"))
	})

	t.Run("SSE watch - agent cannot watch another agents registration", func(t *testing.T) {
		gm := gomega.NewWithT(t)
		reg := &v1alpha1.AgentRegistration{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "sse-other-reg",
				Namespace: testDefaultNS,
			},
			Spec: v1alpha1.AgentRegistrationSpec{
				AgentIdentity: "other-agent",
			},
		}
		gm.Expect(directClient.Create(ctx, reg)).To(gomega.Succeed())
		defer func() {
			if delErr := directClient.Delete(ctx, reg); delErr != nil {
				t.Logf("failed to delete test registration: %v", delErr)
			}
		}()

		s := &Server{
			client:       directClient,
			apiReader:    directClient,
			watchClient:  watchClient,
			waitTimeout:  serverWaitTimeout,
			roles:        newRoleConfig("agent-a", "", "", "", "", ""),
			authRequired: true,
		}

		req := httptest.NewRequest("GET",
			fmt.Sprintf("/agent-registrations/sse-other-reg/watch?namespace=%s", testDefaultNS), nil)
		req.Header.Set("Accept", "text/event-stream")
		req.SetPathValue("name", "sse-other-reg")
		reqCtx := withCallerSub(context.Background(), "agent-a")
		reqCtx = withCallerGroups(reqCtx, []string{})
		req = req.WithContext(reqCtx)
		rr := httptest.NewRecorder()
		s.handleWatchAgentRegistration(rr, req)
		gm.Expect(rr.Code).To(gomega.Equal(http.StatusForbidden))
	})
}
