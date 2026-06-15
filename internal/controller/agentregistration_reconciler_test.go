package controller

import (
	"context"
	"testing"
	"time"

	"github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	governancev1alpha1 "github.com/agent-control-plane/aip-k8s/api/v1alpha1"
)

func newFakeClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().
		WithScheme(newTestScheme()).
		WithStatusSubresource(&governancev1alpha1.AgentRegistration{}).
		WithObjects(objs...).
		Build()
}

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = governancev1alpha1.AddToScheme(s)
	return s
}

func TestAgentRegistrationReconciler_PendingTTLDenial(t *testing.T) {
	gm := gomega.NewWithT(t)
	ctx := context.Background()

	reg := &governancev1alpha1.AgentRegistration{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pending-ttl-test",
			Namespace:         "default",
			CreationTimestamp: metav1.Now(),
		},
		Spec: governancev1alpha1.AgentRegistrationSpec{
			AgentIdentity: "pending-ttl-agent",
		},
	}
	c := newFakeClient(reg)

	r := &AgentRegistrationReconciler{
		Client:     c,
		Scheme:     newTestScheme(),
		PendingTTL: time.Hour,
		Clock:      fixedClock(time.Now().Add(2 * time.Hour)), // 2h > 1h TTL → expired
	}
	_, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: reg.Name, Namespace: reg.Namespace},
	})
	gm.Expect(err).NotTo(gomega.HaveOccurred())

	var updated governancev1alpha1.AgentRegistration
	gm.Expect(c.Get(ctx, types.NamespacedName{Name: reg.Name, Namespace: "default"}, &updated)).To(gomega.Succeed())
	gm.Expect(updated.Status.Phase).To(gomega.Equal(governancev1alpha1.PhaseDenied))

	found := false
	for _, cond := range updated.Status.Conditions {
		if cond.Type == "Denied" && cond.Reason == "PendingTTLExpired" {
			found = true
			break
		}
	}
	gm.Expect(found).To(gomega.BeTrue())
}

func TestAgentRegistrationReconciler_PendingTTLNotExpired(t *testing.T) {
	gm := gomega.NewWithT(t)
	ctx := context.Background()

	reg := &governancev1alpha1.AgentRegistration{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pending-not-expired",
			Namespace:         "default",
			CreationTimestamp: metav1.Now(),
		},
		Spec: governancev1alpha1.AgentRegistrationSpec{
			AgentIdentity: "pending-not-expired-agent",
		},
	}
	c := newFakeClient(reg)

	clockNow := time.Now()
	r := &AgentRegistrationReconciler{
		Client:     c,
		Scheme:     newTestScheme(),
		PendingTTL: time.Hour,
		Clock:      fixedClock(clockNow),
	}
	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: reg.Name, Namespace: reg.Namespace},
	})
	gm.Expect(err).NotTo(gomega.HaveOccurred())
	gm.Expect(result.RequeueAfter).To(gomega.BeNumerically("~", time.Hour, 5*time.Second))

	var updated governancev1alpha1.AgentRegistration
	gm.Expect(c.Get(ctx, types.NamespacedName{Name: reg.Name, Namespace: "default"}, &updated)).To(gomega.Succeed())
	gm.Expect(updated.Status.Phase).To(gomega.BeEmpty())
}

func TestAgentRegistrationReconciler_ServiceBindingInert_NotApproved(t *testing.T) {
	gm := gomega.NewWithT(t)
	ctx := context.Background()

	reg := &governancev1alpha1.AgentRegistration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "inert-not-approved",
			Namespace: "default",
		},
		Spec: governancev1alpha1.AgentRegistrationSpec{
			AgentIdentity: "inert-not-approved-agent",
			ExternalIdentities: []governancev1alpha1.ExternalIdentityBinding{
				{Service: "github"},
			},
		},
		Status: governancev1alpha1.AgentRegistrationStatus{
			Phase: governancev1alpha1.PhaseApproved,
		},
	}
	c := newFakeClient(reg)

	r := &AgentRegistrationReconciler{Client: c, Scheme: newTestScheme()}
	_, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: reg.Name, Namespace: reg.Namespace},
	})
	gm.Expect(err).NotTo(gomega.HaveOccurred())

	var updated governancev1alpha1.AgentRegistration
	gm.Expect(c.Get(ctx, types.NamespacedName{Name: reg.Name, Namespace: "default"}, &updated)).To(gomega.Succeed())
	found := false
	for _, cond := range updated.Status.Conditions {
		if cond.Type == governancev1alpha1.ConditionServiceBindingInert &&
			cond.Reason == governancev1alpha1.ReasonServiceNotApproved {
			found = true
			break
		}
	}
	gm.Expect(found).To(gomega.BeTrue())
}

func TestAgentRegistrationReconciler_ServiceBindingInert_NotFound(t *testing.T) {
	gm := gomega.NewWithT(t)
	ctx := context.Background()

	reg := &governancev1alpha1.AgentRegistration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "inert-not-found",
			Namespace: "default",
		},
		Spec: governancev1alpha1.AgentRegistrationSpec{
			AgentIdentity: "inert-not-found-agent",
			ExternalIdentities: []governancev1alpha1.ExternalIdentityBinding{
				{Service: "svc-exists"},
			},
		},
		Status: governancev1alpha1.AgentRegistrationStatus{
			Phase:            governancev1alpha1.PhaseApproved,
			ApprovedServices: []string{"svc-exists"},
		},
	}
	c := newFakeClient(reg)

	r := &AgentRegistrationReconciler{Client: c, Scheme: newTestScheme()}
	_, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: reg.Name, Namespace: reg.Namespace},
	})
	gm.Expect(err).NotTo(gomega.HaveOccurred())

	var updated governancev1alpha1.AgentRegistration
	gm.Expect(c.Get(ctx, types.NamespacedName{Name: reg.Name, Namespace: "default"}, &updated)).To(gomega.Succeed())
	found := false
	for _, cond := range updated.Status.Conditions {
		if cond.Type == governancev1alpha1.ConditionServiceBindingInert &&
			cond.Reason == governancev1alpha1.ReasonServiceNotFound {
			found = true
			break
		}
	}
	gm.Expect(found).To(gomega.BeTrue())
}

func TestAgentRegistrationReconciler_ServiceBindingInert_Clean(t *testing.T) {
	gm := gomega.NewWithT(t)
	ctx := context.Background()

	mcp := &governancev1alpha1.MCPServer{
		ObjectMeta: metav1.ObjectMeta{Name: "found-svc", Namespace: "default"},
		Spec: governancev1alpha1.MCPServerSpec{
			URL: "http://example.com",
		},
	}
	reg := &governancev1alpha1.AgentRegistration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "inert-clean",
			Namespace: "default",
		},
		Spec: governancev1alpha1.AgentRegistrationSpec{
			AgentIdentity: "inert-clean-agent",
			ExternalIdentities: []governancev1alpha1.ExternalIdentityBinding{
				{Service: "found-svc"},
			},
		},
		Status: governancev1alpha1.AgentRegistrationStatus{
			Phase:            governancev1alpha1.PhaseApproved,
			ApprovedServices: []string{"found-svc"},
		},
	}
	c := newFakeClient(reg, mcp)

	r := &AgentRegistrationReconciler{Client: c, Scheme: newTestScheme()}
	_, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: reg.Name, Namespace: reg.Namespace},
	})
	gm.Expect(err).NotTo(gomega.HaveOccurred())

	var updated governancev1alpha1.AgentRegistration
	gm.Expect(c.Get(ctx, types.NamespacedName{Name: reg.Name, Namespace: "default"}, &updated)).To(gomega.Succeed())
	for _, cond := range updated.Status.Conditions {
		gm.Expect(cond.Type).NotTo(gomega.Equal(governancev1alpha1.ConditionServiceBindingInert))
	}
}

func TestAgentRegistrationReconciler_MaxAgeReAttestation(t *testing.T) {
	gm := gomega.NewWithT(t)
	ctx := context.Background()

	approvedAt := metav1.NewTime(time.Now().Add(-25 * time.Hour))
	reg := &governancev1alpha1.AgentRegistration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "max-age-test",
			Namespace: "default",
		},
		Spec: governancev1alpha1.AgentRegistrationSpec{
			AgentIdentity: "max-age-agent",
		},
		Status: governancev1alpha1.AgentRegistrationStatus{
			Phase:      governancev1alpha1.PhaseApproved,
			ApprovedAt: &approvedAt,
		},
	}
	c := newFakeClient(reg)

	clockNow := time.Now()
	r := &AgentRegistrationReconciler{
		Client: c,
		Scheme: newTestScheme(),
		MaxAge: 24 * time.Hour,
		Clock:  fixedClock(clockNow),
	}
	_, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: reg.Name, Namespace: reg.Namespace},
	})
	gm.Expect(err).NotTo(gomega.HaveOccurred())

	var updated governancev1alpha1.AgentRegistration
	gm.Expect(c.Get(ctx, types.NamespacedName{Name: reg.Name, Namespace: "default"}, &updated)).To(gomega.Succeed())
	gm.Expect(updated.Status.Phase).To(gomega.Equal(governancev1alpha1.PhasePending))

	found := false
	for _, cond := range updated.Status.Conditions {
		if cond.Type == "ReAttestationRequired" && cond.Reason == "MaxAgeExceeded" {
			found = true
			break
		}
	}
	gm.Expect(found).To(gomega.BeTrue())
}
