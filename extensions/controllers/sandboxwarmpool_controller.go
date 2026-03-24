// Copyright 2025 The Kubernetes Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controllers

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	toolscache "k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	sandboxv1alpha1 "sigs.k8s.io/agent-sandbox/api/v1alpha1"
	v1alpha1 "sigs.k8s.io/agent-sandbox/api/v1alpha1"
	sandboxcontrollers "sigs.k8s.io/agent-sandbox/controllers"
	extensionsv1alpha1 "sigs.k8s.io/agent-sandbox/extensions/api/v1alpha1"
)

const (
	sandboxTemplateRefHash = "agents.x-k8s.io/sandbox-template-ref-hash"
	warmPoolSandboxLabel   = "agents.x-k8s.io/warm-pool-sandbox"
)

// SandboxWarmPoolReconciler reconciles a SandboxWarmPool object
type SandboxWarmPoolReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	WarmpoolIndexer toolscache.Indexer
}

//+kubebuilder:rbac:groups=extensions.agents.x-k8s.io,resources=sandboxwarmpools,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=extensions.agents.x-k8s.io,resources=sandboxwarmpools/finalizers,verbs=get;update;patch
//+kubebuilder:rbac:groups=extensions.agents.x-k8s.io,resources=sandboxwarmpools/status,verbs=get;update;patch
//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=agents.x-k8s.io,resources=sandboxes,verbs=get;list;watch;create;update;patch;delete

// Reconcile implements the reconciliation loop for SandboxWarmPool
func (r *SandboxWarmPoolReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Fetch the SandboxWarmPool instance
	warmPool := &extensionsv1alpha1.SandboxWarmPool{}
	if err := r.Get(ctx, req.NamespacedName, warmPool); err != nil {
		if k8serrors.IsNotFound(err) {
			log.Info("SandboxWarmPool resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get SandboxWarmPool")
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !warmPool.DeletionTimestamp.IsZero() {
		log.Info("SandboxWarmPool is being deleted")
		return ctrl.Result{}, nil
	}

	// Save old status for comparison
	oldStatus := warmPool.Status.DeepCopy()

	// Reconcile the pool (create or delete Sandboxes as needed)
	if err := r.reconcilePool(ctx, warmPool); err != nil {
		return ctrl.Result{}, err
	}

	// Update status if it has changed
	if err := r.updateStatus(ctx, oldStatus, warmPool); err != nil {
		log.Error(err, "Failed to update SandboxWarmPool status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// reconcilePool ensures the correct number of pre-allocated sandboxes exist in the pool
func (r *SandboxWarmPoolReconciler) reconcilePool(ctx context.Context, warmPool *extensionsv1alpha1.SandboxWarmPool) error {
	log := log.FromContext(ctx)

	// Compute hash of the warm pool name for the pool label
	poolNameHash := sandboxcontrollers.NameHash(warmPool.Name)

	// We still need this string to update the WarmPool status later
	labelSelector := labels.SelectorFromSet(labels.Set{
		warmPoolSandboxLabel: poolNameHash,
	})

	// --- CHANGE 1: Use a slice of POINTERS ---
	var activeSandboxes []*sandboxv1alpha1.Sandbox
	var allErrors error

	templateHash := sandboxcontrollers.NameHash(warmPool.Spec.TemplateRef.Name)
	rawObjects, err := r.WarmpoolIndexer.ByIndex(sandboxTemplateHashIndex, templateHash)
	if err != nil {
		log.Error(err, "Failed to get sandboxes from indexer")
		return err
	}

	for _, obj := range rawObjects {
		rawSb := obj.(*v1alpha1.Sandbox) // Raw pointer!

		if rawSb.Namespace != warmPool.Namespace {
			continue
		}
		if !rawSb.DeletionTimestamp.IsZero() {
			continue
		}
		if rawSb.Labels[warmPoolSandboxLabel] != poolNameHash {
			continue
		}

		controllerRef := metav1.GetControllerOf(rawSb)

		if controllerRef == nil {
			// Orphaned sandbox - we MUST mutate to adopt, so DeepCopy here!
			log.Info("Adopting orphaned sandbox", "sandbox", rawSb.Name)
			sbToAdopt := rawSb.DeepCopy()
			if err := r.adoptSandbox(ctx, warmPool, sbToAdopt); err != nil {
				log.Error(err, "Failed to adopt sandbox", "sandbox", rawSb.Name)
				allErrors = errors.Join(allErrors, err)
				continue
			}
			activeSandboxes = append(activeSandboxes, sbToAdopt)
		} else if controllerRef.UID == warmPool.UID {
			// Already owned - append the RAW POINTER! 0 bytes allocated.
			activeSandboxes = append(activeSandboxes, rawSb)
		}
	}

	const warmPoolReadinessGracePeriod = 5 * time.Minute
	now := time.Now()
	var healthySandboxes []*sandboxv1alpha1.Sandbox

	for _, sb := range activeSandboxes {
		if !isSandboxReady(sb) && !sb.CreationTimestamp.IsZero() && now.Sub(sb.CreationTimestamp.Time) > warmPoolReadinessGracePeriod {
			// Delete stuck sandbox using a skeleton to protect cache pointer
			deleteSkeleton := &sandboxv1alpha1.Sandbox{
				ObjectMeta: metav1.ObjectMeta{Name: sb.Name, Namespace: sb.Namespace},
			}
			if err := r.Delete(ctx, deleteSkeleton); err != nil {
				allErrors = errors.Join(allErrors, err)
			}
			continue
		}
		healthySandboxes = append(healthySandboxes, sb)
	}
	activeSandboxes = healthySandboxes

	desiredReplicas := warmPool.Spec.Replicas
	currentReplicas := int32(len(activeSandboxes))

	warmPool.Status.Replicas = currentReplicas
	warmPool.Status.Selector = labelSelector.String()

	// Calculate ready replicas
	readyReplicas := int32(0)
	for i := range activeSandboxes {
		if isSandboxReady(activeSandboxes[i]) {
			readyReplicas++
		}
	}
	warmPool.Status.ReadyReplicas = readyReplicas

	if currentReplicas < desiredReplicas {
		for i := int32(0); i < desiredReplicas-currentReplicas; i++ {
			if err := r.createPoolSandbox(ctx, warmPool, poolNameHash); err != nil {
				allErrors = errors.Join(allErrors, err)
			}
		}
	}

	if currentReplicas > desiredReplicas {
		// Sort using pointers
		sort.Slice(activeSandboxes, func(i, j int) bool {
			iReady := isSandboxReady(activeSandboxes[i])
			jReady := isSandboxReady(activeSandboxes[j])
			if iReady != jReady {
				return !iReady
			}
			return activeSandboxes[i].CreationTimestamp.After(activeSandboxes[j].CreationTimestamp.Time)
		})

		for i := int32(0); i < currentReplicas-desiredReplicas && i < int32(len(activeSandboxes)); i++ {
			// Delete excess using skeleton
			deleteSkeleton := &sandboxv1alpha1.Sandbox{
				ObjectMeta: metav1.ObjectMeta{Name: activeSandboxes[i].Name, Namespace: activeSandboxes[i].Namespace},
			}
			if err := r.Delete(ctx, deleteSkeleton); err != nil {
				allErrors = errors.Join(allErrors, err)
			}
		}
	}

	return allErrors
}

// adoptSandbox sets this warmpool as the owner of an orphaned sandbox
func (r *SandboxWarmPoolReconciler) adoptSandbox(ctx context.Context, warmPool *extensionsv1alpha1.SandboxWarmPool, sb *sandboxv1alpha1.Sandbox) error {
	if err := controllerutil.SetControllerReference(warmPool, sb, r.Scheme); err != nil {
		return err
	}
	return r.Update(ctx, sb)
}

// createPoolSandbox creates a full Sandbox CR (with pod template, service, etc.) for the warm pool
func (r *SandboxWarmPoolReconciler) createPoolSandbox(ctx context.Context, warmPool *extensionsv1alpha1.SandboxWarmPool, poolNameHash string) error {
	log := log.FromContext(ctx)

	// Try getting template
	var template *extensionsv1alpha1.SandboxTemplate
	var err error
	if template, err = r.getTemplate(ctx, warmPool); err != nil {
		log.Error(err, "Failed to get sandbox template for warm pool", "warmPoolName", warmPool.Name)
		return err
	}

	// Build labels for the Sandbox CR
	sandboxLabels := map[string]string{
		warmPoolSandboxLabel:   poolNameHash,
		sandboxTemplateRefHash: sandboxcontrollers.NameHash(warmPool.Spec.TemplateRef.Name),
	}

	// Copy template pod labels into sandbox pod template
	podLabels := make(map[string]string)
	for k, v := range template.Spec.PodTemplate.ObjectMeta.Labels {
		podLabels[k] = v
	}
	// Propagate template ref hash to pod template for NetworkPolicy targeting
	podLabels[sandboxTemplateRefHash] = sandboxcontrollers.NameHash(warmPool.Spec.TemplateRef.Name)

	podAnnotations := make(map[string]string)
	for k, v := range template.Spec.PodTemplate.ObjectMeta.Annotations {
		podAnnotations[k] = v
	}

	replicas := int32(1)

	sandbox := &sandboxv1alpha1.Sandbox{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("%s-", warmPool.Name),
			Namespace:    warmPool.Namespace,
			Labels:       sandboxLabels,
		},
		Spec: sandboxv1alpha1.SandboxSpec{
			Replicas: &replicas,
			PodTemplate: sandboxv1alpha1.PodTemplate{
				Spec: *template.Spec.PodTemplate.Spec.DeepCopy(),
				ObjectMeta: sandboxv1alpha1.PodMetadata{
					Labels:      podLabels,
					Annotations: podAnnotations,
				},
			},
		},
	}

	// Enforce a secure-by-default policy by disabling the automatic mounting
	// of the service account token for warm pool sandboxes.
	if sandbox.Spec.PodTemplate.Spec.AutomountServiceAccountToken == nil {
		automount := false
		sandbox.Spec.PodTemplate.Spec.AutomountServiceAccountToken = &automount
	}

	// Enforce DNS secure-by-default for warm pool sandboxes.
	management := template.Spec.NetworkPolicyManagement
	isManaged := management == "" || management == extensionsv1alpha1.NetworkPolicyManagementManaged
	isSecureByDefault := isManaged && template.Spec.NetworkPolicy == nil
	if isSecureByDefault && sandbox.Spec.PodTemplate.Spec.DNSPolicy == "" {
		sandbox.Spec.PodTemplate.Spec.DNSPolicy = corev1.DNSNone
		sandbox.Spec.PodTemplate.Spec.DNSConfig = &corev1.PodDNSConfig{
			Nameservers: []string{"8.8.8.8", "1.1.1.1"},
		}
	}

	// Set controller reference so the Sandbox is owned by the SandboxWarmPool
	if err := ctrl.SetControllerReference(warmPool, sandbox, r.Scheme); err != nil {
		return fmt.Errorf("SetControllerReference for Sandbox failed: %w", err)
	}

	if err := r.Create(ctx, sandbox); err != nil {
		log.Error(err, "Failed to create pool sandbox")
		return err
	}

	log.Info("Created new pool sandbox", "sandbox", sandbox.Name, "poolName", warmPool.Name)
	return nil
}

// updateStatus updates the status of the SandboxWarmPool if it has changed
func (r *SandboxWarmPoolReconciler) updateStatus(ctx context.Context, oldStatus *extensionsv1alpha1.SandboxWarmPoolStatus, warmPool *extensionsv1alpha1.SandboxWarmPool) error {
	log := log.FromContext(ctx)

	// Check if status has changed
	if equality.Semantic.DeepEqual(oldStatus, &warmPool.Status) {
		return nil
	}

	patch := &extensionsv1alpha1.SandboxWarmPool{
		TypeMeta: metav1.TypeMeta{
			APIVersion: extensionsv1alpha1.GroupVersion.String(),
			Kind:       "SandboxWarmPool",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      warmPool.Name,
			Namespace: warmPool.Namespace,
		},
		Status: warmPool.Status,
	}

	// Send the Server-Side Apply request to update the status subresource
	if err := r.Status().Patch(ctx, patch, client.Apply, client.FieldOwner("warmpool-controller"), client.ForceOwnership); err != nil {
		log.Error(err, "Failed to apply SandboxWarmPool status via SSA")
		return err
	}

	log.Info("Updated SandboxWarmPool status", "replicas", warmPool.Status.Replicas)
	return nil
}

func (r *SandboxWarmPoolReconciler) getTemplate(ctx context.Context, warmPool *extensionsv1alpha1.SandboxWarmPool) (*extensionsv1alpha1.SandboxTemplate, error) {
	template := &extensionsv1alpha1.SandboxTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: warmPool.Namespace,
			Name:      warmPool.Spec.TemplateRef.Name,
		},
	}
	if err := r.Get(ctx, client.ObjectKeyFromObject(template), template); err != nil {
		if !k8serrors.IsNotFound(err) {
			err = fmt.Errorf("failed to get sandbox template %q: %w", warmPool.Spec.TemplateRef.Name, err)
		}
		return nil, err
	}

	return template, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *SandboxWarmPoolReconciler) SetupWithManager(mgr ctrl.Manager, concurrentWorkers int) error {

	// Extract the Informer Interface
	informer, err := mgr.GetCache().GetInformer(context.Background(), &v1alpha1.Sandbox{})
	if err != nil {
		return err
	}

	// Unmask the interface to access the raw client-go methods
	sharedInformer, ok := informer.(toolscache.SharedIndexInformer)
	if !ok {
		return fmt.Errorf("failed to cast informer to client-go SharedIndexInformer")
	}

	// Add the custom index directly to the raw client-go Informer
	err = sharedInformer.AddIndexers(toolscache.Indexers{
		sandboxTemplateHashIndex: func(obj interface{}) ([]string, error) {
			sandbox, ok := obj.(*v1alpha1.Sandbox)
			if !ok {
				return nil, nil
			}
			if hash, exists := sandbox.Labels["agents.x-k8s.io/sandbox-template-ref-hash"]; exists {
				return []string{hash}, nil
			}
			return nil, nil
		},
	})

	// Safely catch the conflict using strings.Contains
	if err != nil && !strings.Contains(err.Error(), "indexer conflict") {
		return fmt.Errorf("failed to add raw indexer: %w", err)
	}

	// Safely attach the zero-copy indexer to our controller struct
	r.WarmpoolIndexer = sharedInformer.GetIndexer()

	return ctrl.NewControllerManagedBy(mgr).
		For(&extensionsv1alpha1.SandboxWarmPool{}).
		Owns(&v1alpha1.Sandbox{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: concurrentWorkers}).
		Complete(r)
}
