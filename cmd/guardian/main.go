// Binary guardian is the controller-runtime manager entry point for the
// guardian operator.
//
// GUARDIAN_ROLE is read at the very start of main, before any initialisation.
// An absent or invalid GUARDIAN_ROLE causes an immediate structured exit.
// guardian-schema.md §15.
//
// Controller sets are role-gated:
//   - Both roles: RBACPolicy, RBACProfile, IdentityProvider, IdentityBinding,
//     Bootstrap, PermissionService gRPC.
//   - role=management adds: PermissionSet, EPG, AuditSink.
//   - role=tenant adds: AuditForwarder, TenantSnapshotRunnable, TenantProfileRunnable.
//
// The CNPG migration runner (WS2 session/41) runs before controller registration
// when role=management. guardian-schema.md §3, §16.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	_ "github.com/lib/pq" // registers "postgres" driver for database/sql

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/dynamic"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/controller"
	"github.com/ontai-dev/guardian/internal/database"
	"github.com/ontai-dev/guardian/internal/permissionservice"
	"github.com/ontai-dev/guardian/internal/role"
	"github.com/ontai-dev/guardian/internal/webhook"
	seamv1alpha1 "github.com/ontai-dev/seam-core/api/v1alpha1"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))
	// SeamMembership CRD is owned by seam-core (infrastructure.ontai.dev).
	// Guardian must register it to watch and reconcile SeamMembership objects.
	utilruntime.Must(seamv1alpha1.AddToScheme(scheme))
}

func main() {
	// Read GUARDIAN_ROLE before any other initialisation.
	// An absent or invalid value causes an immediate structured exit.
	// guardian-schema.md §15.
	guardianRole := role.ReadFromEnv()

	// Read OPERATOR_NAMESPACE — the namespace where this operator runs and where
	// namespace-scoped operator CRs (Guardian singleton, PermissionSnapshots) live.
	// Absent value is a hard startup failure: all namespace-scoped writes would land
	// in the wrong namespace without it.
	operatorNamespace := os.Getenv("OPERATOR_NAMESPACE")
	if operatorNamespace == "" {
		fmt.Fprintln(os.Stderr, "OPERATOR_NAMESPACE must be set")
		os.Exit(1)
	}

	// Read MANAGEMENT_CLUSTER_NAME — the name of this management cluster, used to
	// compute seam-tenant-{name} when placing third-party RBACProfiles.
	// Defaults to "ccs-mgmt" for backwards compatibility with the bootstrap bundle.
	managementClusterName := os.Getenv("MANAGEMENT_CLUSTER_NAME")
	if managementClusterName == "" {
		managementClusterName = "ccs-mgmt"
	}

	// Read CLUSTER_ID — this instance's cluster name. Required for role=tenant
	// to filter PermissionSnapshots and name PermissionSnapshotReceipts.
	// guardian-schema.md §7, §8.
	clusterID := os.Getenv("CLUSTER_ID")

	var (
		metricsAddr          string
		healthProbeAddr      string
		enableLeaderElection bool
		webhookPort          int
		grpcAddr             string
	)

	// METRICS_ADDR overrides the metrics bind address. Defaults to :8080.
	// ServiceMonitor CRDs for Prometheus Operator scrape configuration are
	// deferred to a post-e2e observability session.
	metricsDefault := ":8080"
	if v := os.Getenv("METRICS_ADDR"); v != "" {
		metricsDefault = v
	}
	flag.StringVar(&metricsAddr, "metrics-bind-address", metricsDefault,
		"The address the metrics endpoint binds to. Overridden by METRICS_ADDR env var.")
	flag.StringVar(&healthProbeAddr, "health-probe-bind-address", ":8081",
		"The address the health and readiness probes bind to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", true,
		"Enable leader election for controller manager. "+
			"Ensures only one instance is active at a time.")
	flag.IntVar(&webhookPort, "webhook-port", 9443,
		"The port the admission webhook server binds to.")
	flag.StringVar(&grpcAddr, "grpc-address", ":9090",
		"The address the PermissionService gRPC endpoint binds to.")

	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	setupLog := ctrl.Log.WithName("setup")
	setupLog.Info("guardian starting", "role", string(guardianRole))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress:  healthProbeAddr,
		LeaderElection:          enableLeaderElection,
		LeaderElectionID:        "guardian-leader",
		LeaderElectionNamespace: operatorNamespace,
		WebhookServer: ctrlwebhook.NewServer(ctrlwebhook.Options{
			Port: webhookPort,
		}),
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Create the in-memory EPG store shared between EPGReconciler and PermissionService.
	epgStore := permissionservice.NewInMemoryEPGStore()

	// Read PERMISSION_SNAPSHOT_FRESHNESS_WINDOW — the freshness window written into
	// every PermissionSnapshot CR by EPGReconciler. Defaults to 300 (5 minutes).
	freshnessWindow := int64(300)
	if v := os.Getenv("PERMISSION_SNAPSHOT_FRESHNESS_WINDOW"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			freshnessWindow = n
		}
	}

	// For role=management: create the lazy database handle now. The real CNPG
	// connection is established by cnpgStartupRunnable.Start after the
	// controller-runtime informer cache is running. The AuditSinkReconciler
	// holds this handle from construction time; it returns ErrDatabaseNotReady
	// (causing a requeue) until cnpgStartupRunnable calls Set.
	// guardian-schema.md §3 Step 1, §16.
	var lazyAuditDB *database.LazyAuditDatabase
	var auditWriter database.AuditWriter = database.NoopAuditWriter{}
	if guardianRole == role.RoleManagement {
		lazyAuditDB = database.NewLazyAuditDatabase()
		auditWriter = database.NewLazyAuditWriter(lazyAuditDB)
	}

	// For role=tenant: build a dynamic client for the management cluster.
	// MGMT_KUBECONFIG_PATH must point to a kubeconfig with read access to
	// security.ontai.dev PermissionSnapshots on the management cluster.
	// guardian-schema.md §7, §8, §15.
	var mgmtDynClient dynamic.Interface
	if guardianRole == role.RoleTenant {
		mgmtKubeconfigPath := os.Getenv("MGMT_KUBECONFIG_PATH")
		if mgmtKubeconfigPath == "" {
			setupLog.Info("MGMT_KUBECONFIG_PATH not set — TenantSnapshotRunnable disabled")
		} else {
			mgmtCfg, cfgErr := clientcmd.BuildConfigFromFlags("", mgmtKubeconfigPath)
			if cfgErr != nil {
				setupLog.Error(cfgErr, "unable to build management cluster REST config", "path", mgmtKubeconfigPath)
				os.Exit(1)
			}
			mgmtDynClient, err = dynamic.NewForConfig(mgmtCfg)
			if err != nil {
				setupLog.Error(err, "unable to create management cluster dynamic client")
				os.Exit(1)
			}
			setupLog.Info("management cluster client ready", "server", mgmtCfg.Host)
		}
	}

	// Register controllers shared by both roles.
	if err := setupSharedControllers(mgr, auditWriter); err != nil {
		setupLog.Error(err, "unable to set up shared controllers")
		os.Exit(1)
	}

	// Register role-specific controllers.
	if err := setupRoleControllers(mgr, guardianRole, epgStore, lazyAuditDB, auditWriter, operatorNamespace, freshnessWindow, clusterID, mgmtDynClient, managementClusterName); err != nil {
		setupLog.Error(err, "unable to set up role controllers", "role", string(guardianRole))
		os.Exit(1)
	}

	// For role=management: register the CNPG startup runnable. The manager calls
	// Start after the informer cache is synced, so mgr.GetClient().Get() is
	// guaranteed to work when ConnConfigFromSecret reads the CNPG Secret.
	// guardian-schema.md §3 Step 1, §16.
	if guardianRole == role.RoleManagement {
		if err := mgr.Add(&cnpgStartupRunnable{
			kube:   mgr.GetClient(),
			lazyDB: lazyAuditDB,
		}); err != nil {
			setupLog.Error(err, "unable to register CNPG startup runnable")
			os.Exit(1)
		}

		// Register the RBACProfile back-fill runnable. Scans seam-tenant-* namespaces
		// at RBAC_BACKFILL_INTERVAL seconds (default 60) and re-creates any missing
		// RBACProfile CRs for pack components that have a PermissionSet. T-04b.
		backfillInterval := 60 * time.Second
		if v := os.Getenv("RBAC_BACKFILL_INTERVAL"); v != "" {
			if secs, err := strconv.ParseInt(v, 10, 64); err == nil && secs > 0 {
				backfillInterval = time.Duration(secs) * time.Second
			}
		}
		if err := mgr.Add(&controller.RBACProfileBackfillRunnable{
			Client:   mgr.GetClient(),
			Interval: backfillInterval,
		}); err != nil {
			setupLog.Error(err, "unable to register RBACProfile back-fill runnable")
			os.Exit(1)
		}
	}

	// Start the PermissionService gRPC server in the background.
	// Runs in both roles. guardian-schema.md §15.
	svc := permissionservice.NewService(epgStore)
	go func() {
		if err := permissionservice.ListenAndServe(grpcAddr, svc); err != nil {
			setupLog.Error(err, "PermissionService gRPC server failed")
		}
	}()

	// CS-INV-001: admission webhook is the enforcement mechanism.
	// CS-INV-006: leader election enforced by the manager.
	// INV-020: bootstrap RBAC window starts open here.
	modeGate := webhook.NewWebhookModeGate()
	enforcementRegistry := webhook.NewNamespaceEnforcementRegistry()

	// sweepDone is shared between BootstrapAnnotationRunnable (writer) and
	// BootstrapController (reader). The sweep must complete before BootstrapController
	// is permitted to advance WebhookMode to ObserveOnly. guardian-schema.md §4.
	sweepDone := &atomic.Bool{}

	if err := (&controller.BootstrapController{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		Recorder:          mgr.GetEventRecorder("bootstrap-controller"),
		Gate:              modeGate,
		Registry:          enforcementRegistry,
		OperatorNamespace: operatorNamespace,
		SweepDone:         sweepDone,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Bootstrap")
		os.Exit(1)
	}

	bootstrapWindow := webhook.NewBootstrapWindow()
	webhookServer := webhook.NewAdmissionWebhookServer(mgr)
	webhookServer.AuditWriter = auditWriter
	baseResolver := &webhook.KubeNamespaceModeResolver{Client: mgr.GetClient()}
	namespaceModeResolver := webhook.NewGuardedNamespaceModeResolver(baseResolver, modeGate, enforcementRegistry)
	if err := webhookServer.Register(bootstrapWindow, namespaceModeResolver); err != nil {
		setupLog.Error(err, "unable to register admission webhook")
		os.Exit(1)
	}
	webhookServer.RegisterLineage()
	webhookServer.RegisterRBACIntake(mgr.GetClient())
	webhookServer.RegisterPackIntake(mgr.GetClient())
	webhookServer.RegisterOperatorCRGuard(bootstrapWindow, operatorNamespace)
	webhookServer.RegisterDeclaringPrincipal(bootstrapWindow)

	// Register the bootstrap label check as a post-cache Runnable. Runs for both
	// roles. CheckBootstrapLabels reads the operator namespace, which requires
	// the informer cache to be running — it cannot execute before mgr.Start().
	// On failure the Runnable calls os.Exit(1); returning nil allows the manager
	// to continue. guardian-schema.md §4, INV-020.
	if err := mgr.Add(&bootstrapLabelRunnable{
		kube:              mgr.GetClient(),
		operatorNamespace: operatorNamespace,
	}); err != nil {
		setupLog.Error(err, "unable to register bootstrap label runnable")
		os.Exit(1)
	}

	// Register the bootstrap annotation sweep as a post-cache Runnable. Runs for
	// both roles. Scans all pre-existing RBAC resources and stamps the ownership
	// annotation on any resource missing ontai.dev/rbac-owner=guardian. Signals
	// completion via sweepDone, unblocking BootstrapController from advancing
	// WebhookMode to ObserveOnly. guardian-schema.md §4, INV-020.
	// ManagementClusterName is only needed for role=management (third-party profile
	// creation targets seam-tenant-{ManagementClusterName}). For role=tenant,
	// TenantProfileRunnable owns profile creation -- pass "" to skip that step.
	sweepMgmtCluster := managementClusterName
	if guardianRole == role.RoleTenant {
		sweepMgmtCluster = ""
	}
	if err := mgr.Add(&controller.BootstrapAnnotationRunnable{
		Client:                mgr.GetClient(),
		SweepDone:             sweepDone,
		AuditWriter:           auditWriter,
		ManagementClusterName: sweepMgmtCluster,
	}); err != nil {
		setupLog.Error(err, "unable to register bootstrap annotation runnable")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting guardian manager", "role", string(guardianRole))
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// bootstrapLabelRunnable verifies that the operator namespace carries the
// seam.ontai.dev/webhook-mode=exempt label after the informer cache is running.
// Registered via mgr.Add for both roles — the admission webhook requires this
// label regardless of role. CheckBootstrapLabels reads a Kubernetes object, so
// it cannot run before mgr.Start(). On failure, Start logs the error and calls
// os.Exit(1); the manager is shut down.
// guardian-schema.md §4, INV-020, CS-INV-004.
type bootstrapLabelRunnable struct {
	kube              client.Client
	operatorNamespace string
}

func (r *bootstrapLabelRunnable) Start(ctx context.Context) error {
	if err := webhook.CheckBootstrapLabels(ctx, r.kube, r.operatorNamespace); err != nil {
		ctrl.Log.WithName("setup").Error(err,
			"bootstrap label check failed; refusing to continue",
			"namespace", r.operatorNamespace,
			"label", webhook.WebhookModeLabelKey,
			"expected", string(webhook.NamespaceModeExempt),
		)
		os.Exit(1)
	}
	ctrl.Log.WithName("setup").Info("bootstrap label check passed",
		"namespace", r.operatorNamespace,
		"label", webhook.WebhookModeLabelKey,
	)
	return nil
}

// cnpgStartupRunnable initialises the CNPG connection after the controller-runtime
// informer cache has started. It is registered via mgr.Add so that Start is called
// only once the cache is ready and mgr.GetClient() can serve reads.
//
// Start resolves the CNPG connection Secret (ConnConfigFromSecret), opens the
// connection, runs schema migrations (RunWithRetry), and calls lazyDB.Set to make
// AuditSinkReconciler operational. If CNPG is unreachable, RunWithRetry blocks in
// a degraded hold loop (30s retry) per guardian-schema.md §3 Step 1. Returning a
// non-nil error from Start causes the manager to shut down.
//
// guardian-schema.md §3 Step 1, §16.
type cnpgStartupRunnable struct {
	kube   client.Client
	lazyDB *database.LazyAuditDatabase
}

func (r *cnpgStartupRunnable) Start(ctx context.Context) error {
	log := ctrl.Log.WithName("cnpg-startup")
	db, err := database.RunWithRetry(ctx, func() (database.ConnConfig, error) {
		return database.ConnConfigFromSecret(ctx, r.kube)
	}, r.kube)
	if err != nil {
		// ctx cancelled — clean shutdown.
		return fmt.Errorf("CNPG startup aborted: %w", err)
	}
	r.lazyDB.Set(database.NewSQLAuditStore(db))
	log.Info("CNPG ready — flushing pending audit events")
	return nil
}

// setupSharedControllers registers the controllers that run in both roles.
// guardian-schema.md §15.
func setupSharedControllers(mgr ctrl.Manager, aw database.AuditWriter) error {
	if err := (&controller.RBACPolicyReconciler{
		Client:      mgr.GetClient(),
		Scheme:      mgr.GetScheme(),
		Recorder:    mgr.GetEventRecorder("rbacpolicy-controller"),
		AuditWriter: aw,
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	if err := (&controller.RBACProfileReconciler{
		Client:      mgr.GetClient(),
		Scheme:      mgr.GetScheme(),
		Recorder:    mgr.GetEventRecorder("rbacprofile-controller"),
		AuditWriter: aw,
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	if err := (&controller.IdentityBindingReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorder("identitybinding-controller"),
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	if err := (&controller.IdentityProviderReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorder("identityprovider-controller"),
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	// PermissionSnapshotReconciler: runs under both roles.
	// Both management and tenant need freshness tracking. guardian-schema.md §7.
	if err := (&controller.PermissionSnapshotReconciler{
		Client:      mgr.GetClient(),
		Scheme:      mgr.GetScheme(),
		Recorder:    mgr.GetEventRecorder("permissionsnapshot-controller"),
		AuditWriter: aw,
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	// SeamMembershipReconciler: validates SeamMembership CRs against the operator's
	// RBACProfile and admits members to the Seam infrastructure family.
	// Watches infrastructure.ontai.dev/v1alpha1 SeamMembership CRs from seam-core.
	if err := (&controller.SeamMembershipReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	return nil
}

// setupRoleControllers registers the controllers specific to the given role.
// guardian-schema.md §15.
func setupRoleControllers(mgr ctrl.Manager, r role.Role, epgStore *permissionservice.InMemoryEPGStore, auditDB database.AuditDatabase, aw database.AuditWriter, operatorNamespace string, freshnessWindow int64, clusterID string, mgmtDynClient dynamic.Interface, managementClusterName string) error {
	switch r {
	case role.RoleManagement:
		return setupManagementControllers(mgr, epgStore, auditDB, aw, operatorNamespace, freshnessWindow, managementClusterName)
	case role.RoleTenant:
		return setupTenantControllers(mgr, clusterID, operatorNamespace, mgmtDynClient, aw)
	default:
		// ParseRole already prevents this path; guard defensively.
		return nil
	}
}

// setupManagementControllers registers controllers that run only when role=management.
// guardian-schema.md §15, §18, §19.
func setupManagementControllers(mgr ctrl.Manager, epgStore *permissionservice.InMemoryEPGStore, auditDB database.AuditDatabase, aw database.AuditWriter, operatorNamespace string, freshnessWindow int64, managementClusterName string) error {
	// ClusterRBACPolicyReconciler: provisions cluster-level RBACPolicy and PermissionSet
	// for each InfrastructureTalosCluster and cascades deletion. guardian-schema.md §18.
	if err := (&controller.ClusterRBACPolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	if err := (&controller.PermissionSetReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorder("permissionset-controller"),
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	if err := (&controller.EPGReconciler{
		Client:                 mgr.GetClient(),
		Scheme:                 mgr.GetScheme(),
		Recorder:               mgr.GetEventRecorder("epg-controller"),
		Store:                  epgStore,
		OperatorNamespace:      operatorNamespace,
		FreshnessWindowSeconds: freshnessWindow,
		ManagementClusterName:  managementClusterName,
		AuditWriter:            aw,
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	// AuditSinkReconciler receives the LazyAuditDatabase constructed in main.
	// The DB is always non-nil here (management role only). The cnpgStartupRunnable
	// calls Set after the cache starts, making the DB operational. Until then,
	// Reconcile returns ErrDatabaseNotReady and requeues audit batch ConfigMaps.
	// guardian-schema.md §3 Step 1, §16.
	if err := (&controller.AuditSinkReconciler{
		Client:      mgr.GetClient(),
		Scheme:      mgr.GetScheme(),
		Recorder:    mgr.GetEventRecorder("auditsink-controller"),
		DB:          auditDB,
		AuditWriter: aw,
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	return nil
}

// setupTenantControllers registers controllers and runnables that run only when
// role=tenant. guardian-schema.md §15.
//
// TenantSnapshotRunnable: pulls PermissionSnapshot from management cluster,
// writes PermissionSnapshotReceipt to tenant cluster, acknowledges back to
// management, and sets Compliant=True. Requires mgmtDynClient; skipped when nil.
//
// TenantProfileRunnable: creates RBACProfiles in Namespace for each discovered
// third-party component. Runs periodically (60 s). CS-INV-008.
func setupTenantControllers(mgr ctrl.Manager, clusterID, namespace string, mgmtDynClient dynamic.Interface, aw database.AuditWriter) error {
	// AuditForwarderController: full implementation in WS4 session/41.
	auditCh := make(chan controller.AuditForwarderEvent, 256)
	if err := (&controller.AuditForwarderController{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		Recorder:  mgr.GetEventRecorder("auditforwarder-controller"),
		EventCh:   auditCh,
		ClusterID: clusterID,
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	// TenantSnapshotRunnable: guardian role=tenant exclusively owns the
	// PermissionSnapshot acknowledgement and Compliant condition lifecycle.
	// Disabled when MGMT_KUBECONFIG_PATH is absent (mgmtDynClient == nil).
	// guardian-schema.md §7, §8. CS-INV-001.
	if mgmtDynClient != nil {
		if err := mgr.Add(&controller.TenantSnapshotRunnable{
			LocalClient: mgr.GetClient(),
			MgmtClient:  mgmtDynClient,
			ClusterID:   clusterID,
			Namespace:   namespace,
			Interval:    60 * time.Second,
		}); err != nil {
			return fmt.Errorf("register TenantSnapshotRunnable: %w", err)
		}
	}

	// TenantProfileRunnable: creates RBACProfiles for known third-party components
	// in Namespace (ont-system) on the tenant cluster. CS-INV-008 -- no per-component
	// PermissionSet or RBACPolicy is created here.
	if err := mgr.Add(&controller.TenantProfileRunnable{
		Client:      mgr.GetClient(),
		Namespace:   namespace,
		ClusterID:   clusterID,
		Interval:    60 * time.Second,
		AuditWriter: aw,
	}); err != nil {
		return fmt.Errorf("register TenantProfileRunnable: %w", err)
	}

	return nil
}
