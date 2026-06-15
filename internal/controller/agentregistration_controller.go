package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	governancev1alpha1 "github.com/agent-control-plane/aip-k8s/api/v1alpha1"
)

// +kubebuilder:rbac:groups=governance.aip.io,resources=agentregistrations,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=governance.aip.io,resources=agentregistrations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=governance.aip.io,resources=agenttrustprofiles,verbs=get;list;watch;create
// +kubebuilder:rbac:groups=governance.aip.io,resources=mcpservers,verbs=get;list;watch

type AgentRegistrationReconciler struct {
	client.Client
	APIReader  client.Reader
	Scheme     *runtime.Scheme
	PendingTTL time.Duration
	MaxAge     time.Duration
	Clock      func() time.Time
}

func (r *AgentRegistrationReconciler) clock() time.Time {
	if r.Clock != nil {
		return r.Clock()
	}
	return time.Now()
}

func (r *AgentRegistrationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var reg governancev1alpha1.AgentRegistration
	if err := r.Get(ctx, req.NamespacedName, &reg); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to fetch AgentRegistration %s: %w", req.NamespacedName, err)
	}

	now := r.clock()
	phase := reg.Status.Phase

	// PENDING-TTL DENY — only for registrations that have never been approved.
	// Re-attestation (Approved → Pending via MaxAge) keeps ApprovedAt set, so
	// this block is skipped for previously-approved registrations even if their
	// creation timestamp exceeds PendingTTL. Also skip when PendingTTL is 0
	// (disabled).
	if r.PendingTTL > 0 && reg.Status.ApprovedAt == nil &&
		(phase == "" || phase == governancev1alpha1.PhasePending) {
		age := now.Sub(reg.CreationTimestamp.Time)
		if age >= r.PendingTTL {
			base := reg.DeepCopy()
			reg.Status.Phase = governancev1alpha1.PhaseDenied
			meta.SetStatusCondition(&reg.Status.Conditions, metav1.Condition{
				Type:    "Denied",
				Status:  metav1.ConditionTrue,
				Reason:  "PendingTTLExpired",
				Message: fmt.Sprintf("registration was Pending for %v (limit %v)", age.Round(time.Second), r.PendingTTL),
			})
			if err := r.Status().Patch(ctx, &reg, client.MergeFrom(base)); err != nil {
				return ctrl.Result{}, fmt.Errorf("pending-TTL patch for %s: %w", reg.Name, err)
			}
			logger.Info("Denied Pending AgentRegistration", "name", reg.Name, "age", age)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{RequeueAfter: r.PendingTTL - age}, nil
	}

	// MAX-AGE RE-ATTESTATION
	if r.MaxAge > 0 && phase == governancev1alpha1.PhaseApproved && reg.Status.ApprovedAt != nil {
		age := now.Sub(reg.Status.ApprovedAt.Time)
		if age >= r.MaxAge {
			base := reg.DeepCopy()
			reg.Status.Phase = governancev1alpha1.PhasePending
			meta.SetStatusCondition(&reg.Status.Conditions, metav1.Condition{
				Type:    "ReAttestationRequired",
				Status:  metav1.ConditionTrue,
				Reason:  "MaxAgeExceeded",
				Message: fmt.Sprintf("approval exceeded max-age %v; re-attestation required", r.MaxAge),
			})
			if err := r.Status().Patch(ctx, &reg, client.MergeFrom(base)); err != nil {
				return ctrl.Result{}, fmt.Errorf("max-age re-attestation patch for %s: %w", reg.Name, err)
			}
			logger.Info("Transitioned Approved AgentRegistration back to Pending (max-age)",
				"name", reg.Name, "age", age)
			return ctrl.Result{}, nil
		}
	}

	// SERVICE BINDING INERT CONDITIONS
	conditionBase, err := r.reconcileServiceBindingInert(ctx, &reg, phase, req.Namespace)
	if err != nil {
		return ctrl.Result{}, err
	}
	if conditionBase != nil {
		if err := r.Status().Patch(ctx, &reg, client.MergeFrom(conditionBase)); err != nil {
			return ctrl.Result{}, fmt.Errorf("ServiceBindingInert condition patch for %s: %w", reg.Name, err)
		}
	}

	// ATP PRE-CREATE
	atpCreated, err := r.reconcileATPPreCreate(ctx, &reg, phase)
	if err != nil {
		return ctrl.Result{}, err
	}
	if atpCreated {
		logger.Info("Pre-created AgentTrustProfile from AgentRegistration",
			"registration", reg.Name, "agentIdentity", reg.Spec.AgentIdentity)
	}

	// Schedule next requeue
	if r.MaxAge > 0 && phase == governancev1alpha1.PhaseApproved && reg.Status.ApprovedAt != nil {
		remaining := r.MaxAge - now.Sub(reg.Status.ApprovedAt.Time)
		return ctrl.Result{RequeueAfter: remaining}, nil
	}
	return ctrl.Result{}, nil
}

func (r *AgentRegistrationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&governancev1alpha1.AgentRegistration{}).
		Watches(&governancev1alpha1.MCPServer{},
			handler.EnqueueRequestsFromMapFunc(r.mapMCPServerToRegistrations)).
		Complete(r)
}

func (r *AgentRegistrationReconciler) reconcileServiceBindingInert(
	ctx context.Context, reg *governancev1alpha1.AgentRegistration, phase, namespace string,
) (*governancev1alpha1.AgentRegistration, error) {
	if phase != governancev1alpha1.PhaseApproved {
		return nil, nil
	}
	var mcpserverList governancev1alpha1.MCPServerList
	if err := r.List(ctx, &mcpserverList, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("listing MCPServers for ServiceBindingInert check: %w", err)
	}
	liveMCPServers := make(map[string]struct{}, len(mcpserverList.Items))
	for _, m := range mcpserverList.Items {
		liveMCPServers[m.Name] = struct{}{}
	}

	// Capture base before modifications so the status patch computes a correct diff.
	base := reg.DeepCopy()
	oldInertCondition := meta.FindStatusCondition(reg.Status.Conditions, governancev1alpha1.ConditionServiceBindingInert)
	var oldConditionJSON string
	if oldInertCondition != nil {
		b, _ := json.Marshal(oldInertCondition)
		oldConditionJSON = string(b)
	}

	var notApprovedSvcs, notFoundSvcs []string
	for _, binding := range reg.Spec.ExternalIdentities {
		svc := binding.Service
		inApproved := slices.Contains(reg.Status.ApprovedServices, svc)
		if !inApproved {
			notApprovedSvcs = append(notApprovedSvcs, svc)
			continue
		}
		if _, found := liveMCPServers[svc]; !found {
			notFoundSvcs = append(notFoundSvcs, svc)
			continue
		}
	}
	if len(notApprovedSvcs) > 0 || len(notFoundSvcs) > 0 {
		var msg string
		if len(notApprovedSvcs) > 0 {
			msg += fmt.Sprintf("services not in approvedServices: %v; ", notApprovedSvcs)
		}
		if len(notFoundSvcs) > 0 {
			msg += fmt.Sprintf("MCPServers not found: %v", notFoundSvcs)
		}
		reason := governancev1alpha1.ReasonServiceNotApproved
		if len(notApprovedSvcs) == 0 {
			reason = governancev1alpha1.ReasonServiceNotFound
		}
		meta.SetStatusCondition(&reg.Status.Conditions, metav1.Condition{
			Type:    governancev1alpha1.ConditionServiceBindingInert,
			Status:  metav1.ConditionTrue,
			Reason:  reason,
			Message: msg,
		})
	} else {
		meta.RemoveStatusCondition(&reg.Status.Conditions, governancev1alpha1.ConditionServiceBindingInert)
	}

	// Only return a base (triggering a patch) if the condition actually changed.
	newInertCondition := meta.FindStatusCondition(reg.Status.Conditions, governancev1alpha1.ConditionServiceBindingInert)
	var newConditionJSON string
	if newInertCondition != nil {
		b, _ := json.Marshal(newInertCondition)
		newConditionJSON = string(b)
	}
	if oldConditionJSON == newConditionJSON {
		return nil, nil
	}
	return base, nil
}

func (r *AgentRegistrationReconciler) reconcileATPPreCreate(
	ctx context.Context, reg *governancev1alpha1.AgentRegistration, phase string,
) (bool, error) {
	if phase != governancev1alpha1.PhaseApproved {
		return false, nil
	}
	atpName := governancev1alpha1.ProfileNameForAgent(reg.Spec.AgentIdentity)
	var atp governancev1alpha1.AgentTrustProfile
	if err := r.Get(ctx, types.NamespacedName{Name: atpName, Namespace: reg.Namespace}, &atp); err != nil {
		if errors.IsNotFound(err) {
			atp = governancev1alpha1.AgentTrustProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      atpName,
					Namespace: reg.Namespace,
				},
				Spec: governancev1alpha1.AgentTrustProfileSpec{
					AgentIdentity: reg.Spec.AgentIdentity,
				},
			}
			if setRefErr := controllerutil.SetControllerReference(reg, &atp, r.Scheme); setRefErr != nil {
				return false, fmt.Errorf("setting owner reference on AgentTrustProfile %s: %w", atpName, setRefErr)
			}
			if createErr := r.Create(ctx, &atp); createErr != nil && !errors.IsAlreadyExists(createErr) {
				return false, fmt.Errorf("creating AgentTrustProfile %s: %w", atpName, createErr)
			}
			return true, nil
		}
		return false, fmt.Errorf("fetching AgentTrustProfile %s: %w", atpName, err)
	}
	return false, nil
}

func (r *AgentRegistrationReconciler) mapMCPServerToRegistrations(ctx context.Context, obj client.Object) []reconcile.Request {
	var regList governancev1alpha1.AgentRegistrationList
	if err := r.List(ctx, &regList, client.InNamespace(obj.GetNamespace())); err != nil {
		log.FromContext(ctx).Error(err, "failed to list AgentRegistrations for MCPServer watch",
			"MCPServer", obj.GetName(), "namespace", obj.GetNamespace())
		return nil
	}
	reqs := make([]reconcile.Request, 0, len(regList.Items))
	for _, reg := range regList.Items {
		reqs = append(reqs, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name: reg.Name, Namespace: reg.Namespace,
			},
		})
	}
	return reqs
}
